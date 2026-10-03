package pl.aibron.aigate.policy;

import java.util.List;

public record ClientSpec(
        String id,
        String apiKeySha256,
        String profile,
        List<String> models,
        ToolPolicy tools,
        Budgets budgets) {

    public record ToolPolicy(List<String> allowed, List<String> denyArgumentPatterns) {

        public ToolPolicy {
            allowed = allowed == null ? List.of() : List.copyOf(allowed);
            denyArgumentPatterns = denyArgumentPatterns == null ? List.of() : List.copyOf(denyArgumentPatterns);
        }
    }

    public ClientSpec {
        models = models == null ? List.of() : List.copyOf(models);
        tools = tools == null ? new ToolPolicy(List.of(), List.of()) : tools;
    }

    public boolean mayUse(String model) {
        return models.contains(model);
    }
}
