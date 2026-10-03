package pl.aibron.aigate.inspection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The stub model echoes what it received, so the response shows exactly what the model saw.
 */
@DisplayName("Request content: profile decides allow / redact / block")
class RequestContentPolicyTest extends GatewayTestSupport {

    private static final String WITH_PESEL = "Check credit history for client 44051401359 please";
    private static final String WITH_SECRET = "Why does this fail? aws_access_key_id = AKIAIOSFODNN7EXAMPLE";

    @Test
    @DisplayName("allowed: request with no sensitive data is forwarded unchanged")
    void cleanRequest() {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", "Summarise the PSD2 directive in two sentences");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("Summarise the PSD2 directive in two sentences");
    }

    @Test
    @DisplayName("redacted: balanced profile masks a PESEL before the model sees it")
    void balancedRedactsPii() {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", WITH_PESEL);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("client [PESEL] please").doesNotContain("44051401359");
    }

    @Test
    @DisplayName("blocked: strict profile refuses a request containing a PESEL")
    void strictBlocksPii() {
        var response = chat(FINANCE_APP_KEY, "llama3.2:3b", WITH_PESEL);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body())
                .contains("\"category\":\"sensitive_data\"")
                .contains("PESEL")
                .doesNotContain("44051401359");
    }

    @Test
    @DisplayName("allowed: permissive profile lets PII through")
    void permissiveAllowsPii() {
        var response = chat(SANDBOX_KEY, "llama3.2:3b", WITH_PESEL);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("44051401359");
    }

    @Test
    @DisplayName("blocked: balanced profile refuses a request containing a cloud credential")
    void balancedBlocksSecret() {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", WITH_SECRET);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("\"category\":\"secret\"").doesNotContain("AKIAIOSFODNN7EXAMPLE");
    }

    @Test
    @DisplayName("redacted: permissive profile masks a secret instead of blocking")
    void permissiveRedactsSecret() {
        var response = chat(SANDBOX_KEY, "llama3.2:3b", WITH_SECRET);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("[SECRET]").doesNotContain("AKIAIOSFODNN7EXAMPLE");
    }

    @Test
    @DisplayName("redacted: PII in a multi-part message (content array) is masked too")
    void contentParts() {
        var response = post(DEMO_AGENT_KEY, """
                {"model":"llama3.2:3b","messages":[{"role":"user","content":[
                  {"type":"text","text":"Contact jan.kowalski@bank.pl about it"}]}]}
                """);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).doesNotContain("jan.kowalski@bank.pl");
    }
}
