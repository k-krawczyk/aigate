package pl.aibron.aigate.identity;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;

import pl.aibron.aigate.GatewayTestSupport;
import pl.aibron.aigate.policy.PolicyStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A local JWKS endpoint plays the corporate IdP. Tokens are signed here with a fresh RSA key; the gateway only
 * knows the public half, from the JWKS, exactly as with Entra ID or Keycloak.
 */
@DirtiesContext
@DisplayName("Access control: corporate IdP (OIDC access tokens)")
class OidcAuthenticationTest extends GatewayTestSupport {

    private static final String ISSUER = "http://idp.test/realms/bank";
    private static final String AUDIENCE = "aigate";
    private static RSAKey idpKey;
    private static HttpServer jwksServer;

    @Autowired
    PolicyStore store;

    @Autowired
    JdbcTemplate jdbc;

    @BeforeAll
    static void startIdp() throws Exception {
        idpKey = new RSAKeyGenerator(2048).keyID("idp-key-1").generate();
        var jwks = new JWKSet(idpKey.toPublicJWK()).toString();
        jwksServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        jwksServer.createContext("/certs", exchange -> {
            var bytes = jwks.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        jwksServer.start();

        var policy = Files.readString(POLICY_DIR.resolve("policy.yaml"));
        Files.writeString(POLICY_DIR.resolve("policy.yaml"), policy + """

                identity:
                  oidc:
                    - name: corporate
                      issuer: %s
                      jwks_uri: http://localhost:%d/certs
                      audience: %s
                      client_claim: azp
                      user_claim: preferred_username
                      groups_claim: groups
                      group_profiles:
                        ai-finance: strict
                        ai-interns: permissive
                """.formatted(ISSUER, jwksServer.getAddress().getPort(), AUDIENCE));
    }

    @AfterAll
    static void stopIdp() throws Exception {
        jwksServer.stop(0);
        Files.copy(Path.of("src/test/resources/policy/policy.yaml"), POLICY_DIR.resolve("policy.yaml"),
                StandardCopyOption.REPLACE_EXISTING);
    }

    @BeforeEach
    void awaitIdentityConfig() throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (store.current().identity().oidc().isEmpty()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("identity section never loaded: " + store.lastReload());
            }
            Thread.sleep(100);
        }
    }

    private static JWTClaimsSet.Builder claims() {
        var now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER).audience(AUDIENCE).subject("f3a1c2d4")
                .claim("azp", "demo-agent").claim("preferred_username", "jan.kowalski")
                .claim("groups", List.of("ai-staff"))
                .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300)));
    }

    private static String sign(JWTClaimsSet claims) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(idpKey.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(idpKey));
        return jwt.serialize();
    }

    @Test
    @DisplayName("allowed: valid token, agent from azp, person recorded as on-behalf-of in the audit")
    void validToken() throws Exception {
        var response = chat(sign(claims().build()), "llama3.2:3b", "hello from the IdP");

        assertThat(response.statusCode()).isEqualTo(200);
        var id = response.headers().firstValue("X-AIGate-Request-Id").orElseThrow();
        var row = awaitRow(id);
        assertThat(row).containsEntry("CLIENT_ID", "demo-agent").containsEntry("ON_BEHALF_OF", "jan.kowalski")
                .containsEntry("AUTH_METHOD", "oidc:corporate");
    }

    @Test
    @DisplayName("tightened: group ai-finance maps to strict, so PII is blocked instead of redacted")
    void groupTightensProfile() throws Exception {
        var plain = chat(sign(claims().build()), "llama3.2:3b", "client 44051401359");
        var finance = chat(sign(claims().claim("groups", List.of("ai-staff", "ai-finance")).build()),
                "llama3.2:3b", "client 44051401359");

        assertThat(plain.statusCode()).isEqualTo(200);
        assertThat(finance.statusCode()).isEqualTo(403);
        assertThat(finance.body()).contains("\"category\":\"sensitive_data\"");
        // The SOC must be able to explain the different outcome: same agent, different person, different profile.
        var plainRow = awaitRow(plain.headers().firstValue("X-AIGate-Request-Id").orElseThrow());
        var financeRow = awaitRow(finance.body().replaceAll("(?s).*\"audit_id\":\"([^\"]+)\".*", "$1"));
        assertThat(plainRow).containsEntry("PROFILE", "balanced").containsEntry("CALLER_GROUPS", "ai-staff");
        assertThat(financeRow).containsEntry("PROFILE", "strict").containsEntry("CALLER_GROUPS", "ai-staff,ai-finance")
                .containsEntry("AUTH_METHOD", "oidc:corporate");
    }

    @Test
    @DisplayName("never loosened: a group mapped to permissive cannot relax the client's balanced profile")
    void groupCannotLoosen() throws Exception {
        var response = chat(sign(claims().claim("groups", List.of("ai-interns")).build()),
                "llama3.2:3b", "Why does this fail? AKIAIOSFODNN7EXAMPLE");

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    @DisplayName("blocked: expired token")
    void expired() throws Exception {
        var past = Instant.now().minusSeconds(3600);
        var token = sign(claims().issueTime(Date.from(past)).expirationTime(Date.from(past.plusSeconds(60))).build());

        assertThat(chat(token, "llama3.2:3b", "hello").statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("blocked: token issued for another audience")
    void wrongAudience() throws Exception {
        assertThat(chat(sign(claims().audience("payments-api").build()), "llama3.2:3b", "hello").statusCode())
                .isEqualTo(401);
    }

    @Test
    @DisplayName("blocked: token from another issuer")
    void wrongIssuer() throws Exception {
        assertThat(chat(sign(claims().issuer("http://evil.test").build()), "llama3.2:3b", "hello").statusCode())
                .isEqualTo(401);
    }

    @Test
    @DisplayName("blocked: token signed with a key the IdP never published")
    void foreignKey() throws Exception {
        var attacker = new RSAKeyGenerator(2048).keyID("idp-key-1").generate();
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("idp-key-1").build(), claims().build());
        jwt.sign(new RSASSASigner(attacker));

        assertThat(chat(jwt.serialize(), "llama3.2:3b", "hello").statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("blocked: unsigned token (alg none)")
    void algNone() throws Exception {
        var token = new PlainJWT(claims().build()).serialize();

        assertThat(chat(token, "llama3.2:3b", "hello").statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("blocked: HMAC token signed with a guessable secret (algorithm confusion)")
    void hmacConfusion() throws Exception {
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims().build());
        jwt.sign(new MACSigner("0123456789abcdef0123456789abcdef"));

        assertThat(chat(jwt.serialize(), "llama3.2:3b", "hello").statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("blocked: valid token for an agent that is not a client in the policy")
    void unknownClient() throws Exception {
        assertThat(chat(sign(claims().claim("azp", "shadow-agent").build()), "llama3.2:3b", "hello").statusCode())
                .isEqualTo(401);
    }

    @Test
    @DisplayName("allowed: API keys keep working next to the IdP")
    void apiKeyStillWorks() {
        assertThat(chat(DEMO_AGENT_KEY, "llama3.2:3b", "hello with a key").statusCode()).isEqualTo(200);
    }

    private Map<String, Object> awaitRow(String id) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            var rows = jdbc.queryForList("SELECT * FROM audit_event WHERE id = ?", id);
            if (!rows.isEmpty()) {
                return rows.getFirst();
            }
            Thread.sleep(50);
        }
        throw new AssertionError("no audit event " + id);
    }
}
