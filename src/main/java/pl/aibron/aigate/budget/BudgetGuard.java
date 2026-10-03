package pl.aibron.aigate.budget;

import java.time.Instant;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.gateway.ExchangeKeys;
import pl.aibron.aigate.gateway.GatewayRejection;
import pl.aibron.aigate.policy.ClientSpec;
import pl.aibron.aigate.policy.Policy;

/** Pipeline steps for OWASP LLM10 (unbounded consumption). */
@Component
public class BudgetGuard {

    public static final String CATEGORY = "unbounded_consumption";
    public static final String OWASP = "LLM10";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final BudgetLedger ledger;
    private final LoopBreaker loopBreaker;
    private final boolean blockWhenStoreDown;

    public BudgetGuard(BudgetLedger ledger, LoopBreaker loopBreaker,
                       @org.springframework.beans.factory.annotation.Value("${aigate.budget.on-store-error:allow}")
                       String onStoreError) {
        this.ledger = ledger;
        this.loopBreaker = loopBreaker;
        this.blockWhenStoreDown = "block".equalsIgnoreCase(onStoreError);
    }

    public void admit(Exchange exchange) {
        var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
        var client = exchange.getProperty(ExchangeKeys.CLIENT, ClientSpec.class);
        var budgets = policy.budgetsOf(client);
        BudgetLedger.Usage used;
        try {
            used = ledger.usage(client.id(), budgets.windowDuration());
        } catch (BudgetStoreUnavailableException e) {
            if (blockWhenStoreDown) {
                throw new GatewayRejection(503, "budget_store_unavailable", CATEGORY, OWASP,
                        "Budget store unavailable, try again later");
            }
            // Availability over accuracy: the request goes on unmetered, counted in aigate.budget.store.errors.
            used = BudgetLedger.Usage.NONE;
        }

        if (budgets.maxTokens() != null && used.tokens() >= budgets.maxTokens()) {
            reject("token_budget_exceeded", "Token budget of " + budgets.maxTokens() + " per " + budgets.window()
                    + " is used up");
        }
        if (budgets.maxCostUsd() != null && used.costUsd() >= budgets.maxCostUsd()) {
            reject("cost_budget_exceeded", "Cost budget of USD " + budgets.maxCostUsd() + " per " + budgets.window()
                    + " is used up");
        }
        if (budgets.maxModelSeconds() != null && used.modelSeconds() >= budgets.maxModelSeconds()) {
            reject("compute_budget_exceeded", "Model time budget of " + budgets.maxModelSeconds() + " s per "
                    + budgets.window() + " is used up");
        }

        var loop = budgets.loopBreaker();
        if (loop != null) {
            var request = exchange.getProperty(ExchangeKeys.REQUEST, ObjectNode.class);
            int similar = loopBreaker.similarRecent(client.id(), request, loop.withinDuration(), loop.similarity());
            if (similar >= loop.maxSimilarRequests()) {
                reject("loop_detected", "Loop detected: " + (similar + 1) + " near-identical requests within "
                        + loop.within());
            }
        }
    }

    /** Charged right after the model answers, before response checks, so a blocked answer still costs. */
    public void charge(Exchange exchange) {
        var status = exchange.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE, 200, Integer.class);
        if (status != 200) {
            return;
        }
        var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
        var client = exchange.getProperty(ExchangeKeys.CLIENT, ClientSpec.class);
        var model = exchange.getProperty(ExchangeKeys.MODEL, String.class);
        long promptTokens = 0;
        long completionTokens = 0;
        try {
            var usage = JSON.readTree(exchange.getMessage().getBody(String.class)).path("usage");
            promptTokens = usage.path("prompt_tokens").asLong();
            completionTokens = usage.path("completion_tokens").asLong();
        } catch (Exception e) {
            // No usage block: charge model time only.
        }
        final long in = promptTokens;
        final long out = completionTokens;
        double cost = policy.model(model).map(m -> m.cost(in, out)).orElse(0.0);
        @SuppressWarnings("unchecked")
        var steps = (Map<String, Long>) exchange.getProperty(ExchangeKeys.STEP_TIMINGS, Map.class);
        long modelMillis = steps == null ? 0 : steps.getOrDefault("upstream", 0L) / 1000;

        ledger.charge(client.id(), new BudgetLedger.Charge(Instant.now(), in + out, cost, modelMillis),
                policy.budgetsOf(client).windowDuration());
        exchange.setProperty(ExchangeKeys.USAGE_TOKENS, new long[] {in, out});
        exchange.setProperty(ExchangeKeys.COST_USD, cost);
    }

    private static void reject(String code, String message) {
        throw new GatewayRejection(429, code, CATEGORY, OWASP, message);
    }
}
