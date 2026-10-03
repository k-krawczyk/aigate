package pl.aibron.aigate.policy;

import java.util.List;

public record ClientSpec(
        String id,
        String apiKeySha256,
        String profile,
        List<String> models,
        ToolPolicy tools,
        Budgets budgets) {

    /**
     * @param pinned tool name to the SHA-256 (hex) of the description that was reviewed and approved; a tool whose
     *     description no longer matches (an MCP server changed it after approval) is refused
     */
    public record ToolPolicy(List<String> allowed, List<String> denyArgumentPatterns,
                             java.util.Map<String, String> pinned) {

        public ToolPolicy {
            allowed = allowed == null ? List.of() : List.copyOf(allowed);
            denyArgumentPatterns = denyArgumentPatterns == null ? List.of() : List.copyOf(denyArgumentPatterns);
            pinned = pinned == null ? java.util.Map.of() : java.util.Map.copyOf(pinned);
        }
    }

    public ClientSpec {
        models = models == null ? List.of() : List.copyOf(models);
        tools = tools == null ? new ToolPolicy(List.of(), List.of(), null) : tools;
    }

    public boolean mayUse(String model) {
        return models.contains(model);
    }
}
