package pl.aibron.aigate.policy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * Parses and validates the policy file. Validation collects every problem at once, so an operator who breaks
 * the file sees the full list on the dashboard instead of fixing errors one reload at a time.
 */
public final class PolicyLoader {

    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");

    private static final ObjectMapper YAML = JsonMapper.builder(new YAMLFactory())
            .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
            // Unknown keys are almost always typos; silently ignoring them would leave a control switched off.
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private PolicyLoader() {
    }

    public static Policy load(Path file) throws InvalidPolicyException {
        try {
            return parse(Files.readString(file));
        } catch (IOException e) {
            throw new InvalidPolicyException(List.of("cannot read " + file + ": " + e.getMessage()));
        }
    }

    public static Policy parse(String yaml) throws InvalidPolicyException {
        Policy policy;
        try {
            policy = YAML.readValue(yaml, Policy.class);
        } catch (JsonProcessingException e) {
            throw new InvalidPolicyException(List.of("YAML: " + e.getOriginalMessage()));
        }
        if (policy == null) {
            throw new InvalidPolicyException(List.of("policy file is empty"));
        }
        var errors = validate(policy);
        if (!errors.isEmpty()) {
            throw new InvalidPolicyException(errors);
        }
        return policy;
    }

    static List<String> validate(Policy policy) {
        var errors = new ArrayList<String>();
        if (policy.version() != 1) {
            errors.add("version: expected 1, got " + policy.version());
        }
        if (policy.profiles().isEmpty()) {
            errors.add("profiles: at least one profile is required");
        }
        policy.profiles().forEach((name, profile) -> {
            var risk = profile.risk();
            if (!inUnitRange(risk.unsureAbove()) || !inUnitRange(risk.blockAbove())) {
                errors.add("profiles." + name + ".risk: thresholds must be between 0 and 1");
            } else if (risk.unsureAbove() > risk.blockAbove()) {
                errors.add("profiles." + name + ".risk: unsure_above must not exceed block_above");
            }
            var guard = profile.guardThresholds();
            if (!inUnitRange(guard.harmful()) || !inUnitRange(guard.injection())) {
                errors.add("profiles." + name + ".guard_thresholds: thresholds must be between 0 and 1");
            }
        });

        var modelNames = new HashSet<String>();
        for (var model : policy.models()) {
            if (model.name() == null || model.name().isBlank()) {
                errors.add("models: every model needs a name");
            } else if (!modelNames.add(model.name())) {
                errors.add("models: duplicate model " + model.name());
            }
            if (model.pricePer1kInput() < 0 || model.pricePer1kOutput() < 0) {
                errors.add("models." + model.name() + ": prices must not be negative");
            }
        }

        validateBudgets("budgets", policy.budgets(), errors);
        if (policy.signatures() != null && policy.signatures().refresh() != null) {
            checkDuration("signatures.refresh", policy.signatures().refresh(), errors);
        }

        var clientIds = new HashSet<String>();
        var keyHashes = new HashSet<String>();
        for (var client : policy.clients()) {
            var prefix = "clients." + client.id();
            if (client.id() == null || client.id().isBlank()) {
                errors.add("clients: every client needs an id");
                continue;
            }
            if (!clientIds.add(client.id())) {
                errors.add(prefix + ": duplicate client id");
            }
            if (client.apiKeySha256() == null || !SHA256_HEX.matcher(client.apiKeySha256()).matches()) {
                errors.add(prefix + ".api_key_sha256: expected 64 lowercase hex characters");
            } else if (!keyHashes.add(client.apiKeySha256())) {
                errors.add(prefix + ".api_key_sha256: same key as another client");
            }
            if (!policy.profiles().containsKey(client.profile())) {
                errors.add(prefix + ".profile: unknown profile '" + client.profile() + "'");
            }
            for (var model : client.models()) {
                if (!modelNames.contains(model)) {
                    errors.add(prefix + ".models: '" + model + "' is not declared under models");
                }
            }
            for (var pattern : client.tools().denyArgumentPatterns()) {
                try {
                    Pattern.compile(pattern);
                } catch (PatternSyntaxException e) {
                    errors.add(prefix + ".tools.deny_argument_patterns: invalid regex '" + pattern + "'");
                }
            }
            if (client.budgets() != null) {
                validateBudgets(prefix + ".budgets", client.budgets(), errors);
            }
        }
        return errors;
    }

    private static void validateBudgets(String path, Budgets budgets, List<String> errors) {
        if (budgets.window() != null) {
            checkDuration(path + ".window", budgets.window(), errors);
        }
        if (budgets.maxTokens() != null && budgets.maxTokens() < 0
                || budgets.maxCostUsd() != null && budgets.maxCostUsd() < 0
                || budgets.maxModelSeconds() != null && budgets.maxModelSeconds() < 0) {
            errors.add(path + ": limits must not be negative");
        }
        var loop = budgets.loopBreaker();
        if (loop != null) {
            checkDuration(path + ".loop_breaker.within", loop.within(), errors);
            if (loop.maxSimilarRequests() < 1) {
                errors.add(path + ".loop_breaker.max_similar_requests: must be at least 1");
            }
            if (!inUnitRange(loop.similarity())) {
                errors.add(path + ".loop_breaker.similarity: must be between 0 and 1");
            }
        }
    }

    private static void checkDuration(String path, String value, List<String> errors) {
        try {
            Durations.parse(value);
        } catch (IllegalArgumentException e) {
            errors.add(path + ": " + e.getMessage());
        }
    }

    private static boolean inUnitRange(double value) {
        return value >= 0 && value <= 1;
    }
}
