package pl.aibron.aigate.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Gateway pass-through")
class PassThroughTest extends GatewayTestSupport {

    @Test
    @DisplayName("allowed: benign chat completion reaches the model and the answer comes back unchanged")
    void forwardsBenignRequest() {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", "What is the capital of Poland?");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(StubUpstream.MODEL_REPLY_PREFIX + "What is the capital of Poland?");
        assertThat(response.headers().firstValue("X-AIGate-Request-Id")).isPresent();
    }

    @Test
    @DisplayName("blocked: body that is not JSON gets 400 in OpenAI error format")
    void rejectsInvalidJson() {
        var response = post(DEMO_AGENT_KEY, "not json");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("\"type\":\"invalid_request_error\"");
    }
}
