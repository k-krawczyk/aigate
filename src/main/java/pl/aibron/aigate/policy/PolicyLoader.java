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

        for (var sink : policy.audit().sinks()) {
            if (sink.type() == null) {
                errors.add("audit.sinks: every sink needs a type (syslog or splunk_hec)");
                continue;
            }
            var path = "audit.sinks." + sink.label();
            switch (sink.type()) {
                case SYSLOG -> {
                    if (sink.host() == null || sink.host().isBlank()) {
                        errors.add(path + ".host: required for syslog");
                    }
                    if (sink.port() == null || sink.port() < 1 || sink.port() > 65535) {
                        errors.add(path + ".port: must be 1-65535");
                    }
                }
                case KAFKA -> {
                    if (sink.bootstrapServers() == null || sink.bootstrapServers().isBlank()) {
                        errors.add(path + ".bootstrap_servers: required, e.g. kafka:9092");
                    }
                    if (sink.topic() == null || !sink.topic().matches("[A-Za-z0-9._-]{1,249}")) {
                        errors.add(path + ".topic: required, letters, digits, '.', '_' or '-'");
                    }
                    if (sink.saslMechanism() != null && !sink.saslMechanism().matches("PLAIN|SCRAM-SHA-256|SCRAM-SHA-512")) {
                        errors.add(path + ".sasl_mechanism: PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512");
                    }
                    if (sink.saslMechanism() != null && (sink.saslUsername() == null || sink.saslPasswordEnv() == null)) {
                        errors.add(path + ": sasl_mechanism needs sasl_username and sasl_password_env");
                    }
                }
                case SPLUNK_HEC -> {
                    if (sink.url() == null || !sink.url().matches("https?://.+")) {
                        errors.add(path + ".url: required, http(s) URL of the HEC event endpoint");
                    }
                    if (sink.tokenEnv() == null || sink.tokenEnv().isBlank()) {
                        errors.add(path + ".token_env: name of the environment variable with the HEC token");
                    }
                    if (sink.batchSize() != null && (sink.batchSize() < 1 || sink.batchSize() > 1000)) {
                        errors.add(path + ".batch_size: must be 1-1000");
                    }
                    if (sink.batchInterval() != null) {
                        checkDuration(path + ".batch_interval", sink.batchInterval(), errors);
                    }
                }
            }
        }

        var providerNames = new HashSet<String>();
        for (var provider : policy.identity().oidc()) {
            var path = "identity.oidc." + provider.name();
            if (provider.name() == null || !providerNames.add(provider.name())) {
                errors.add("identity.oidc: every provider needs a unique name");
            }
            if (provider.issuer() == null || !provider.issuer().matches("https?://.+")) {
                errors.add(path + ".issuer: required, the issuer URL exactly as in the token's iss claim");
            }
            if (provider.audience() == null || provider.audience().isBlank()) {
                errors.add(path + ".audience: required, tokens for other audiences must be refused");
            }
            if (provider.serviceAccountPattern() != null) {
                try {
                    Pattern.compile(provider.serviceAccountPattern());
                } catch (PatternSyntaxException e) {
                    errors.add(path + ".service_account_pattern: invalid regex");
                }
            }
            provider.groupProfiles().forEach((group, profile) -> {
                if (!policy.profiles().containsKey(profile)) {
                    errors.add(path + ".group_profiles." + group + ": unknown profile '" + profile + "'");
                }
            });
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
            // A client may authenticate only through the corporate IdP, so the key hash is optional.
            if (client.apiKeySha256() != null && !SHA256_HEX.matcher(client.apiKeySha256()).matches()) {
                errors.add(prefix + ".api_key_sha256: expected 64 lowercase hex characters");
            } else if (client.apiKeySha256() != null && !keyHashes.add(client.apiKeySha256())) {
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
