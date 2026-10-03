package pl.aibron.aigate.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

import org.springframework.stereotype.Component;

import pl.aibron.aigate.policy.Policy;

/**
 * Bearer API keys. The policy stores only SHA-256 hashes, so the policy file itself is not a credential store.
 */
@Component
public class ApiKeyResolver implements IdentityResolver {

    private static final String BEARER = "Bearer ";

    @Override
    public Resolution resolve(String authorizationHeader, Policy policy) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return Resolution.notApplicable();
        }
        var token = authorizationHeader.substring(BEARER.length()).trim();
        if (IdentityResolver.looksLikeJwt(token)) {
            return Resolution.notApplicable();
        }
        var presented = sha256(token);
        return policy.clients().stream()
                .filter(c -> c.apiKeySha256() != null)
                .filter(c -> MessageDigest.isEqual(presented, HexFormat.of().parseHex(c.apiKeySha256())))
                .findFirst()
                .map(c -> Resolution.accepted(new CallerIdentity(c.id(), c.id(), null, List.of(), "api_key", null)))
                .orElseGet(() -> Resolution.rejected("auth.api_key_unknown", "API key matches no client"));
    }

    public static String sha256Hex(String key) {
        return HexFormat.of().formatHex(sha256(key));
    }

    private static byte[] sha256(String key) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JDK", e);
        }
    }
}
