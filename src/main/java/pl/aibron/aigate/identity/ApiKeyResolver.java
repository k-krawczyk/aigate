package pl.aibron.aigate.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Component;

import pl.aibron.aigate.policy.Policy;

/**
 * Bearer API keys. The policy stores only SHA-256 hashes, so the policy file itself is not a credential store.
 */
@Component
public class ApiKeyResolver implements IdentityResolver {

    private static final String BEARER = "Bearer ";

    @Override
    public Optional<CallerIdentity> resolve(String authorizationHeader, Policy policy) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            return Optional.empty();
        }
        var presented = sha256(authorizationHeader.substring(BEARER.length()).trim());
        return policy.clients().stream()
                .filter(c -> MessageDigest.isEqual(presented, HexFormat.of().parseHex(c.apiKeySha256())))
                .findFirst()
                .map(c -> new CallerIdentity(c.id(), c.id(), null, List.of(), "api_key"));
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
