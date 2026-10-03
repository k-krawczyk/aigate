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
import pl.aibron.aigate.identity.Resolution;
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
        Resolution rejection = null;
        CallerIdentity identity = null;
        for (var resolver : identityResolvers) {
            var resolution = resolver.resolve(header, policy);
            if (resolution.isAccepted()) {
                identity = resolution.identity();
                break;
            }
            if (resolution.isRejected() && rejection == null) {
                rejection = resolution;
            }
        }
        if (identity == null) {
            if (rejection == null) {
                rejection = Resolution.rejected("auth.missing_credentials", "no Bearer credential in the request");
            }
            exchange.setProperty(ExchangeKeys.AUTH_RULE, rejection.rule());
            exchange.setProperty(ExchangeKeys.AUTH_DETAIL, rejection.detail());
            if (rejection.knownCaller() != null) {
                exchange.setProperty(ExchangeKeys.IDENTITY, rejection.knownCaller());
            }
            // Same answer for every reason, so a caller cannot probe which part of a credential failed.
            throw new GatewayRejection(401, "invalid_api_key", "access_control", "Missing or invalid credentials");
        }
        var client = policy.client(identity.clientId()).orElseThrow();
        // IdP groups can tighten the client's profile for this caller, setting by setting, never loosen it.
        var profile = policy.profiles().get(client.profile());
        var applied = new java.util.ArrayList<String>(List.of(client.profile()));
        for (var groupProfile : identity.groupProfiles()) {
            var merged = profile.stricterOf(policy.profiles().get(groupProfile));
            if (!merged.equals(profile)) {
                applied.add(groupProfile);
                profile = merged;
            }
        }
        exchange.setProperty(ExchangeKeys.IDENTITY, identity);
        exchange.setProperty(ExchangeKeys.CLIENT, client);
        exchange.setProperty(ExchangeKeys.PROFILE_NAME, applied.size() == 1 ? client.profile()
                : merged(applied, profile, policy));
        exchange.setProperty(ExchangeKeys.PROFILE, profile);
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

    /**
     * Audit name of the effective profile: the group profile alone when it is at least as strict as the client's
     * on every setting (the usual case, e.g. "strict"), otherwise the names joined with '+'.
     */
    private static String merged(List<String> applied, pl.aibron.aigate.policy.Profile effective, Policy policy) {
        var last = applied.getLast();
        return effective.equals(policy.profiles().get(last)) ? last : String.join("+", applied);
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
