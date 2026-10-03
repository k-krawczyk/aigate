package pl.aibron.aigate.policy;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The whole policy file. Immutable: a reload builds a new instance and swaps it atomically.
 */
public record Policy(
        int version,
        Map<String, Profile> profiles,
        List<ModelSpec> models,
        Budgets budgets,
        Signatures signatures,
        List<ClientSpec> clients,
        AuditConfig audit) {

    public Policy {
        profiles = profiles == null ? Map.of() : Map.copyOf(profiles);
        models = models == null ? List.of() : List.copyOf(models);
        clients = clients == null ? List.of() : List.copyOf(clients);
        budgets = budgets == null ? Budgets.NONE : budgets;
        audit = audit == null ? AuditConfig.NONE : audit;
    }

    public Optional<ModelSpec> model(String name) {
        return models.stream().filter(m -> m.name().equals(name)).findFirst();
    }

    public Optional<ClientSpec> client(String id) {
        return clients.stream().filter(c -> c.id().equals(id)).findFirst();
    }

    public Profile profileOf(ClientSpec client) {
        return profiles.get(client.profile());
    }

    /** Client-level limits win; anything the client leaves out falls back to the global budget. */
    public Budgets budgetsOf(ClientSpec client) {
        return client.budgets() == null ? budgets : client.budgets().withDefaults(budgets);
    }
}
