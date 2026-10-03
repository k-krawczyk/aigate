package pl.aibron.aigate.identity;

import java.util.List;

/**
 * Who is calling. For an agent acting for a person, {@code clientId} is the agent and {@code onBehalfOf} the person,
 * so the audit trail keeps both. {@code groupProfiles} are the profiles the caller's IdP groups map to.
 */
public record CallerIdentity(
        String clientId,
        String subject,
        String onBehalfOf,
        List<String> groups,
        String authMethod,
        List<String> groupProfiles) {

    public CallerIdentity {
        groups = groups == null ? List.of() : List.copyOf(groups);
        groupProfiles = groupProfiles == null ? List.of() : List.copyOf(groupProfiles);
    }
}
