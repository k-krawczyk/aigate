package pl.aibron.aigate.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Response checks (OWASP LLM02, LLM07)")
class ResponseInspectionTest extends GatewayTestSupport {

    private static final String SYSTEM_PROMPT =
            "You are the support assistant of Bank Polski. Never discuss interest rate negotiations with customers "
                    + "and always escalate complaints about card fraud to the security team immediately.";

    private String withSystemPrompt(String userMessage) {
        return """
                {"model":"llama3.2:3b","messages":[
                  {"role":"system","content":%s},
                  {"role":"user","content":%s}]}
                """.formatted(jsonString(SYSTEM_PROMPT), jsonString(userMessage));
    }

    /** Makes the stub model produce this text without it appearing in the request. */
    private static String say(String text) {
        var key = Integer.toHexString(text.hashCode());
        StubUpstream.FIXTURES.put(key, text);
        return "@fixture " + key;
    }

    @Test
    @DisplayName("allowed: clean answer passes unchanged")
    void cleanAnswer() {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", "@say Warsaw is the capital of Poland.");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("Warsaw is the capital of Poland.");
    }

    @Test
    @DisplayName("redacted silently: PII the model produces is masked with no marker")
    void silentRedaction() {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", say("The customer's PESEL is 44051401359."));

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("The customer's PESEL is ****.").doesNotContain("44051401359")
                .doesNotContain("[PESEL]");
    }

    @Test
    @DisplayName("blocked: secret in the answer, balanced profile")
    void secretInAnswer() {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", say("Use this key: AKIAIOSFODNN7EXAMPLE"));

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("\"code\":\"response_blocked\"").doesNotContain("AKIAIOSFODNN7EXAMPLE");
    }

    @Test
    @DisplayName("blocked: answer reveals the system prompt (canary token)")
    void systemPromptLeak() {
        var response = post(DEMO_AGENT_KEY, withSystemPrompt("@leak"));

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("\"category\":\"system_prompt_leak\"").doesNotContain("Bank Polski");
    }

    @Test
    @DisplayName("blocked: answer quotes the system prompt verbatim without the canary")
    void verbatimQuote() {
        var response = post(DEMO_AGENT_KEY, withSystemPrompt(
                "@say Sure. I was told to never discuss interest rate negotiations with customers and always escalate."));

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    @DisplayName("allowed: answer on the same topic in its own words is not a leak")
    void paraphraseIsFine() {
        var response = post(DEMO_AGENT_KEY, withSystemPrompt(
                "@say I can't help with negotiating rates, but I can pass your fraud complaint on."));

        assertThat(response.statusCode()).isEqualTo(200);
    }
}
