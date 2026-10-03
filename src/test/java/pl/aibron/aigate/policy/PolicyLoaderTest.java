package pl.aibron.aigate.policy;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Policy: parsing and validation")
class PolicyLoaderTest {

    private static String shippedPolicy() throws Exception {
        return Files.readString(Path.of("policy/policy.yaml"));
    }

    @Test
    @DisplayName("allowed: the shipped policy/policy.yaml is valid")
    void shippedPolicyIsValid() throws Exception {
        var policy = PolicyLoader.parse(shippedPolicy());

        assertThat(policy.profiles()).containsKeys("strict", "balanced", "permissive");
        assertThat(policy.client("demo-agent")).isPresent();
    }

    @Test
    @DisplayName("allowed: client budgets override only the fields they set")
    void clientBudgetOverride() throws Exception {
        var policy = PolicyLoader.parse(shippedPolicy());
        var budgets = policy.budgetsOf(policy.client("demo-agent").orElseThrow());

        assertThat(budgets.maxTokens()).isEqualTo(50000);
        assertThat(budgets.maxCostUsd()).isEqualTo(5.00);
    }

    @Test
    @DisplayName("blocked: client referencing an unknown profile")
    void unknownProfile() throws Exception {
        var yaml = shippedPolicy().replace("profile: strict", "profile: paranoid");

        assertThatThrownBy(() -> PolicyLoader.parse(yaml))
                .isInstanceOf(InvalidPolicyException.class)
                .hasMessageContaining("unknown profile 'paranoid'");
    }

    @Test
    @DisplayName("blocked: misspelled key is an error, not silently ignored")
    void unknownKey() throws Exception {
        var yaml = shippedPolicy().replace("on_secret: block", "on_secrets: block");

        assertThatThrownBy(() -> PolicyLoader.parse(yaml))
                .isInstanceOf(InvalidPolicyException.class)
                .hasMessageContaining("on_secrets");
    }

    @Test
    @DisplayName("blocked: invalid regex in tool argument deny patterns")
    void invalidRegex() throws Exception {
        var yaml = shippedPolicy().replace("\"\\\\.\\\\./\"", "\"([unclosed\"");

        assertThatThrownBy(() -> PolicyLoader.parse(yaml))
                .isInstanceOf(InvalidPolicyException.class)
                .hasMessageContaining("invalid regex");
    }

    @Test
    @DisplayName("blocked: API key stored in plain text instead of its SHA-256")
    void plainTextKey() throws Exception {
        var yaml = shippedPolicy().replaceFirst("api_key_sha256: [0-9a-f]{64}", "api_key_sha256: my-secret-key");

        assertThatThrownBy(() -> PolicyLoader.parse(yaml))
                .isInstanceOf(InvalidPolicyException.class)
                .hasMessageContaining("64 lowercase hex");
    }

    @Test
    @DisplayName("blocked: unsure threshold above block threshold, and every error is reported at once")
    void collectsAllErrors() throws Exception {
        var yaml = shippedPolicy()
                .replace("risk: { unsure_above: 0.3, block_above: 0.8 }", "risk: { unsure_above: 0.9, block_above: 0.8 }")
                .replace("window: 1h", "window: one hour");

        assertThatThrownBy(() -> PolicyLoader.parse(yaml))
                .isInstanceOfSatisfying(InvalidPolicyException.class, e -> assertThat(e.errors()).hasSize(2));
    }

    @Test
    @DisplayName("blocked: client granted a model that is not declared")
    void undeclaredModel() throws Exception {
        var yaml = shippedPolicy().replace("models: [llama3.2:3b, granite4:3b]", "models: [llama3.2:3b, mixtral:8x7b]");

        assertThatThrownBy(() -> PolicyLoader.parse(yaml))
                .isInstanceOf(InvalidPolicyException.class)
                .hasMessageContaining("'mixtral:8x7b' is not declared");
    }
}
