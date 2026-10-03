package pl.aibron.aigate.identity;

import java.util.List;

/**
 * Who is calling. For an agent acting for a person, {@code clientId} is the agent and {@code onBehalfOf} the person,
 * so the audit trail keeps both.
 */
public record CallerIdentity(
        String clientId,
        String subject,
        String onBehalfOf,
        List<String> groups,
        String authMethod) {

    public CallerIdentity {
        groups = groups == null ? List.of() : List.copyOf(groups);
    }
}
