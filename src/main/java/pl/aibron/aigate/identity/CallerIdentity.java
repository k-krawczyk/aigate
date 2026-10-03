package pl.aibron.aigate.identity;

import java.util.List;

/**
 * Who is calling. For an agent acting for a person, {@code clientId} is the agent and {@code onBehalfOf} the person,
 * so the audit trail keeps both. {@code profileOverride} is set when the caller's IdP groups map to a profile.
 */
public record CallerIdentity(
        String clientId,
        String subject,
        String onBehalfOf,
        List<String> groups,
        String authMethod,
        String profileOverride) {

    public CallerIdentity {
        groups = groups == null ? List.of() : List.copyOf(groups);
    }
}
