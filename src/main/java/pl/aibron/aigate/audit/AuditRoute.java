package pl.aibron.aigate.audit;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.gateway.Decision;
import pl.aibron.aigate.gateway.ExchangeKeys;
import pl.aibron.aigate.identity.CallerIdentity;
import pl.aibron.aigate.inspection.Finding;
import pl.aibron.aigate.policy.Policy;
import pl.aibron.aigate.policy.PolicyStore;

/**
 * Receives wire-tapped exchanges, so audit runs after the response has gone and never adds latency to it.
 */
@Component
public class AuditRoute extends RouteBuilder {

    private static final Logger log = LoggerFactory.getLogger(AuditRoute.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final List<AuditSink> sinks;

    public AuditRoute(List<AuditSink> sinks) {
        this.sinks = List.copyOf(sinks);
    }

    @Override
    public void configure() {
        from("direct:audit").routeId("audit")
                .process(exchange -> publish(fromChatExchange(exchange)));

        from("direct:audit-policy-reload").routeId("audit-policy-reload")
                .process(exchange -> publish(fromReload(exchange.getMessage().getBody(PolicyStore.ReloadOutcome.class),
                        exchange.getMessage().getHeader("revision", Integer.class))));
    }

    public void publish(AuditEvent event) {
        for (var sink : sinks) {
            try {
                sink.publish(event);
            } catch (RuntimeException e) {
                log.warn("Audit sink {} failed for event {}: {}", sink.name(), event.id(), e.getMessage());
            }
        }
    }

    static AuditEvent fromChatExchange(Exchange exchange) {
        var identity = exchange.getProperty(ExchangeKeys.IDENTITY, CallerIdentity.class);
        var status = exchange.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE, Integer.class);
        var decision = exchange.getProperty(ExchangeKeys.DECISION, Decision.class);
        if (decision == null) {
            decision = status != null && status >= 400 ? Decision.BLOCK : Decision.ALLOW;
        }
        @SuppressWarnings("unchecked")
        List<Finding> findings = exchange.getProperty(ExchangeKeys.FINDINGS, List.class);
        @SuppressWarnings("unchecked")
        Map<String, Long> steps = exchange.getProperty(ExchangeKeys.STEP_TIMINGS, Map.class);
        Long started = exchange.getProperty(ExchangeKeys.STARTED_NANOS, Long.class);
        var model = exchange.getProperty(ExchangeKeys.MODEL, String.class);

        Long promptTokens = null;
        Long completionTokens = null;
        Double cost = null;
        var charged = exchange.getProperty(ExchangeKeys.USAGE_TOKENS, long[].class);
        if (charged != null) {
            promptTokens = charged[0];
            completionTokens = charged[1];
            cost = exchange.getProperty(ExchangeKeys.COST_USD, Double.class);
        } else if (status == null || status == 200) {
            var usage = usageOf(exchange.getMessage().getBody(String.class));
            if (usage != null) {
                promptTokens = usage.path("prompt_tokens").asLong();
                completionTokens = usage.path("completion_tokens").asLong();
                var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
                final long in = promptTokens;
                final long out = completionTokens;
                cost = policy == null || model == null ? null
                        : policy.model(model).map(m -> m.cost(in, out)).orElse(null);
            }
        }

        var rejection = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
        return new AuditEvent(
                exchange.getProperty(ExchangeKeys.REQUEST_ID, UUID.randomUUID().toString(), String.class),
                Instant.now(),
                AuditEvent.CHAT,
                identity == null ? null : identity.clientId(),
                identity == null ? null : identity.subject(),
                identity == null ? null : identity.onBehalfOf(),
                identity == null ? null : identity.authMethod(),
                model,
                exchange.getProperty(ExchangeKeys.DIRECTION, String.class),
                decision.name(),
                exchange.getProperty(ExchangeKeys.CATEGORY, String.class),
                exchange.getProperty(ExchangeKeys.OWASP, String.class),
                findings == null || findings.isEmpty() ? null
                        : findings.stream().map(Finding::detector).distinct().collect(Collectors.joining(",")),
                exchange.getProperty(ExchangeKeys.EXCERPT, String.class),
                status == null ? 200 : status,
                promptTokens,
                completionTokens,
                cost,
                started == null ? null : (System.nanoTime() - started) / 1_000_000.0,
                steps == null ? null : new LinkedHashMap<>(steps),
                exchange.getProperty(ExchangeKeys.POLICY_REVISION, Integer.class),
                rejection == null ? null : rejection.getMessage());
    }

    static AuditEvent fromReload(PolicyStore.ReloadOutcome outcome, Integer revision) {
        return new AuditEvent(UUID.randomUUID().toString(), outcome.at(), AuditEvent.POLICY_RELOAD,
                null, null, null, null, null, null,
                outcome.applied() ? "APPLIED" : "REJECTED", "policy", null, null, null, null,
                null, null, null, null, null, revision,
                outcome.errors().isEmpty() ? null : String.join("; ", outcome.errors()));
    }

    private static JsonNode usageOf(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            var usage = JSON.readTree(body).get("usage");
            return usage == null || usage.isNull() ? null : usage;
        } catch (Exception e) {
            return null;
        }
    }
}
