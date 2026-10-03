package pl.aibron.aigate.identity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Access control: API key authentication")
class AuthenticationTest extends GatewayTestSupport {

    @Test
    @DisplayName("allowed: known API key")
    void knownKey() {
        assertThat(chat(DEMO_AGENT_KEY, "llama3.2:3b", "hello").statusCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("blocked: request without Authorization header gets 401")
    void missingKey() {
        var response = chat(null, "llama3.2:3b", "hello");

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).contains("\"code\":\"invalid_api_key\"").contains("\"audit_id\"");
    }

    @Test
    @DisplayName("blocked: unknown API key gets 401")
    void unknownKey() {
        assertThat(chat("aigate-stolen-key", "llama3.2:3b", "hello").statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("blocked: the key's hash itself is not accepted as a key")
    void hashIsNotAKey() {
        var hash = ApiKeyResolver.sha256Hex(DEMO_AGENT_KEY);

        assertThat(chat(hash, "llama3.2:3b", "hello").statusCode()).isEqualTo(401);
    }
}
