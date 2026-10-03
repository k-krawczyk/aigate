package pl.aibron.aigate.identity;

import pl.aibron.aigate.policy.Policy;

/**
 * Turns the Authorization header into a caller. API keys and corporate IdP tokens are two implementations; the
 * pipeline asks each and takes the first acceptance, or else the most specific rejection.
 */
public interface IdentityResolver {

    Resolution resolve(String authorizationHeader, Policy policy);

    /** Three base64url segments: a JWT, whatever its signature algorithm. */
    static boolean looksLikeJwt(String token) {
        return token.chars().filter(c -> c == '.').count() == 2 && token.startsWith("eyJ");
    }
}
