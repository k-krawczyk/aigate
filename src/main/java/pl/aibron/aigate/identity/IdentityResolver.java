package pl.aibron.aigate.identity;

import java.util.Optional;

import pl.aibron.aigate.policy.Policy;

/**
 * Turns the Authorization header into a caller. API keys are the first implementation; a corporate IdP plugs in
 * here as an OIDC JWT resolver without touching the pipeline.
 */
public interface IdentityResolver {

    Optional<CallerIdentity> resolve(String authorizationHeader, Policy policy);
}
