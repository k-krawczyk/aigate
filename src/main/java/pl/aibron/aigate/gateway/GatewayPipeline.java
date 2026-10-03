package pl.aibron.aigate.gateway;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.identity.CallerIdentity;
import pl.aibron.aigate.identity.IdentityResolver;
import pl.aibron.aigate.policy.ClientSpec;
import pl.aibron.aigate.policy.Policy;
import pl.aibron.aigate.policy.PolicyStore;

@Component
public class GatewayPipeline {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final PolicyStore policyStore;
    private final List<IdentityResolver> identityResolvers;

    public GatewayPipeline(PolicyStore policyStore, List<IdentityResolver> identityResolvers) {
        this.policyStore = policyStore;
        this.identityResolvers = identityResolvers;
    }

    public void begin(Exchange exchange) {
        var active = policyStore.active();
        exchange.setProperty(ExchangeKeys.STARTED_NANOS, System.nanoTime());
        exchange.setProperty(ExchangeKeys.REQUEST_ID, UUID.randomUUID().toString());
        exchange.setProperty(ExchangeKeys.POLICY, active.policy());
        exchange.setProperty(ExchangeKeys.POLICY_REVISION, active.revision());
        exchange.setProperty(ExchangeKeys.STEP_TIMINGS, new LinkedHashMap<String, Long>());

        var body = exchange.getMessage().getBody(String.class);
        try {
            if (body == null || body.isBlank() || !(JSON.readTree(body) instanceof ObjectNode request)) {
                throw new GatewayRejection(400, "invalid_request", "request", "Request body must be a JSON object");
            }
            StreamAdapter.captureStreamFlag(exchange, request);
            exchange.setProperty(ExchangeKeys.REQUEST, request);
        } catch (JsonProcessingException e) {
            throw new GatewayRejection(400, "invalid_request", "request", "Request body is not valid JSON");
        }
    }

    public void authenticate(Exchange exchange) {
        var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
        var header = exchange.getMessage().getHeader("Authorization", String.class);
        var identity = identityResolvers.stream()
                .flatMap(r -> r.resolve(header, policy).stream())
                .findFirst()
                .orElseThrow(() -> new GatewayRejection(401, "invalid_api_key", "access_control",
                        "Missing or invalid credentials"));
        var client = policy.client(identity.clientId()).orElseThrow();
        // An IdP group can tighten the client's profile for this caller, never loosen it.
        var profileName = client.profile();
        if (identity.profileOverride() != null && policy.profiles().get(identity.profileOverride()).strictness()
                > policy.profiles().get(profileName).strictness()) {
            profileName = identity.profileOverride();
        }
        exchange.setProperty(ExchangeKeys.IDENTITY, identity);
        exchange.setProperty(ExchangeKeys.CLIENT, client);
        exchange.setProperty(ExchangeKeys.PROFILE_NAME, profileName);
        exchange.setProperty(ExchangeKeys.PROFILE, policy.profiles().get(profileName));
    }

    public void authorizeModel(Exchange exchange) {
        var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
        var client = exchange.getProperty(ExchangeKeys.CLIENT, ClientSpec.class);
        var request = exchange.getProperty(ExchangeKeys.REQUEST, ObjectNode.class);
        var model = request.path("model").asText("");
        if (model.isEmpty()) {
            throw new GatewayRejection(400, "invalid_request", "request", "Field 'model' is required");
        }
        if (policy.model(model).isEmpty() || !client.mayUse(model)) {
            throw new GatewayRejection(403, "model_not_allowed", "access_control",
                    "Model '" + model + "' is not allowed for this client");
        }
        exchange.setProperty(ExchangeKeys.MODEL, model);
    }

    /** Wraps a step so its duration lands in the per-request timing map used by audit and metrics. */
    public static org.apache.camel.Processor timed(String step, org.apache.camel.Processor processor) {
        return exchange -> {
            long start = System.nanoTime();
            try {
                processor.process(exchange);
            } finally {
                @SuppressWarnings("unchecked")
                var timings = (Map<String, Long>) exchange.getProperty(ExchangeKeys.STEP_TIMINGS, Map.class);
                if (timings != null) {
                    timings.put(step, (System.nanoTime() - start) / 1000);
                }
            }
        };
    }

    /** For steps that are a route call rather than a single processor. */
    public static org.apache.camel.Processor startStep(String step) {
        return exchange -> exchange.setProperty(stepStartKey(step), System.nanoTime());
    }

    public static org.apache.camel.Processor endStep(String step) {
        return exchange -> {
            Long start = exchange.getProperty(stepStartKey(step), Long.class);
            @SuppressWarnings("unchecked")
            var timings = (Map<String, Long>) exchange.getProperty(ExchangeKeys.STEP_TIMINGS, Map.class);
            if (start != null && timings != null) {
                timings.put(step, (System.nanoTime() - start) / 1000);
            }
        };
    }

    private static String stepStartKey(String step) {
        return "aigate.stepStart." + step;
    }

    public static CallerIdentity identity(Exchange exchange) {
        return exchange.getProperty(ExchangeKeys.IDENTITY, CallerIdentity.class);
    }
}
