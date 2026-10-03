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

    /**
     * @param serviceAccountPattern regex for user-claim values that name a service account rather than a person
     *     (Keycloak client credentials: {@code ^service-account-}). A match leaves on_behalf_of empty, so
     *     detections keyed on people do not count agents. No default: Entra ID app tokens carry no user claim.
     */
    public record OidcProvider(String name, String issuer, String jwksUri, String audience, String clientClaim,
                               String userClaim, String groupsClaim, Map<String, String> groupProfiles,
                               String serviceAccountPattern) {

        public OidcProvider {
            clientClaim = clientClaim == null ? "azp" : clientClaim;
            userClaim = userClaim == null ? "sub" : userClaim;
            groupsClaim = groupsClaim == null ? "groups" : groupsClaim;
            groupProfiles = groupProfiles == null ? Map.of() : Map.copyOf(groupProfiles);
        }

        public boolean isServiceAccount(String user) {
            return serviceAccountPattern != null && user != null
                    && java.util.regex.Pattern.compile(serviceAccountPattern).matcher(user).find();
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
