package pl.aibron.aigate.policy;

import java.util.List;
import java.util.Map;

/**
 * Corporate identity providers whose tokens AIGate accepts besides API keys.
 *
 * <p>An OIDC access token is mapped to a policy client through {@code client_claim} (the agent or app, usually
 * {@code azp}); the person the agent acts for comes from {@code user_claim} and is recorded in the audit trail.
 * Group membership can tighten the profile: the strictest profile among the caller's mapped groups wins.
 */
public record IdentityConfig(List<OidcProvider> oidc) {

    public static final IdentityConfig NONE = new IdentityConfig(List.of());

    public record OidcProvider(String name, String issuer, String jwksUri, String audience, String clientClaim,
                               String userClaim, String groupsClaim, Map<String, String> groupProfiles) {

        public OidcProvider {
            clientClaim = clientClaim == null ? "azp" : clientClaim;
            userClaim = userClaim == null ? "sub" : userClaim;
            groupsClaim = groupsClaim == null ? "groups" : groupsClaim;
            groupProfiles = groupProfiles == null ? Map.of() : Map.copyOf(groupProfiles);
        }

        /** Explicit JWKS URI, or the conventional location under the issuer (Keycloak, most IdPs). */
        public String effectiveJwksUri() {
            if (jwksUri != null && !jwksUri.isBlank()) {
                return jwksUri;
            }
            return issuer.replaceAll("/+$", "") + "/protocol/openid-connect/certs";
        }
    }

    public IdentityConfig {
        oidc = oidc == null ? List.of() : List.copyOf(oidc);
    }
}
