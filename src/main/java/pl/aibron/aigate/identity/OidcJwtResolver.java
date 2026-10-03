package pl.aibron.aigate.identity;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.policy.IdentityConfig.OidcProvider;
import pl.aibron.aigate.policy.Policy;

/**
 * Accepts access tokens from the corporate IdP (Entra ID, Keycloak, Okta, any OIDC provider). Checks the signature
 * against the provider's JWKS, plus iss, aud, exp and nbf; only asymmetric algorithms are accepted, so neither
 * "alg": "none" nor an HMAC token signed with the public key gets through.
 */
@Component
@Order(1)
public class OidcJwtResolver implements IdentityResolver {

    private static final Logger log = LoggerFactory.getLogger(OidcJwtResolver.class);
    private static final String BEARER = "Bearer ";
    private static final Set<JWSAlgorithm> ALLOWED_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256, JWSAlgorithm.ES256, JWSAlgorithm.ES384);

    /** One cached, rate-limited JWKS source per URI; keys are refetched when an unknown kid appears. */
    private final Map<String, JWKSource<SecurityContext>> jwkSources = new ConcurrentHashMap<>();

    @Override
    public Optional<CallerIdentity> resolve(String authorizationHeader, Policy policy) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return Optional.empty();
        }
        var token = authorizationHeader.substring(BEARER.length()).trim();
        if (token.chars().filter(c -> c == '.').count() != 2 || policy.identity().oidc().isEmpty()) {
            return Optional.empty();
        }
        for (var provider : policy.identity().oidc()) {
            try {
                var claims = processor(provider).process(token, null);
                return Optional.ofNullable(toIdentity(provider, claims, policy));
            } catch (Exception e) {
                // Expected for every provider but the one that issued the token; logged for troubleshooting only.
                log.debug("Token rejected by provider {}: {}", provider.name(), e.getMessage());
            }
        }
        return Optional.empty();
    }

    private DefaultJWTProcessor<SecurityContext> processor(OidcProvider provider) throws Exception {
        var processor = new DefaultJWTProcessor<SecurityContext>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ALLOWED_ALGORITHMS, jwkSource(provider)));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                provider.audience(),
                new JWTClaimsSet.Builder().issuer(provider.issuer()).build(),
                new HashSet<>(List.of("exp", "iat", "iss"))));
        return processor;
    }

    private JWKSource<SecurityContext> jwkSource(OidcProvider provider) throws Exception {
        var uri = provider.effectiveJwksUri();
        var source = jwkSources.get(uri);
        if (source == null) {
            URL url = URI.create(uri).toURL();
            source = JWKSourceBuilder.create(url).retrying(true).build();
            jwkSources.put(uri, source);
        }
        return source;
    }

    private static CallerIdentity toIdentity(OidcProvider provider, JWTClaimsSet claims, Policy policy)
            throws Exception {
        var clientId = claims.getStringClaim(provider.clientClaim());
        if (clientId == null || policy.client(clientId).isEmpty()) {
            log.debug("Valid token from {} for unknown client {}", provider.name(), clientId);
            return null;
        }
        var user = claims.getStringClaim(provider.userClaim());
        var groups = new ArrayList<String>();
        var rawGroups = claims.getClaim(provider.groupsClaim());
        if (rawGroups instanceof List<?> list) {
            list.forEach(g -> groups.add(String.valueOf(g)));
        }
        return new CallerIdentity(clientId, claims.getSubject(), user != null && !user.equals(clientId) ? user : null,
                groups, "oidc:" + provider.name(), strictestProfile(provider, groups, policy));
    }

    /**
     * Profiles are ranked by how they treat PII and when they call the guard models; with several mapped groups the
     * strictest one wins, so adding a person to a lenient group can never weaken a strict one.
     */
    static String strictestProfile(OidcProvider provider, List<String> groups, Policy policy) {
        String best = null;
        int bestRank = -1;
        for (var group : groups) {
            var profileName = provider.groupProfiles().get(group);
            if (profileName == null) {
                continue;
            }
            int rank = policy.profiles().get(profileName).strictness();
            if (rank > bestRank) {
                best = profileName;
                bestRank = rank;
            }
        }
        return best;
    }
}
