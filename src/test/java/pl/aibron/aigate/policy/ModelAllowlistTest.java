package pl.aibron.aigate.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Access control: model allowlist")
class ModelAllowlistTest extends GatewayTestSupport {

    @Test
    @DisplayName("allowed: client uses a model granted to it")
    void grantedModel() {
        assertThat(chat(FINANCE_APP_KEY, "llama3.2:3b", "hello").statusCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("blocked: model declared in policy but not granted to this client gets 403")
    void notGrantedModel() {
        var response = chat(DEMO_AGENT_KEY, "gpt-4o", "hello");

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("\"code\":\"model_not_allowed\"");
    }

    @Test
    @DisplayName("blocked: model unknown to the policy gets 403")
    void unknownModel() {
        assertThat(chat(SANDBOX_KEY, "deepseek-r1:70b", "hello").statusCode()).isEqualTo(403);
    }
}
