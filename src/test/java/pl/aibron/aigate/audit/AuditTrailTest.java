package pl.aibron.aigate.audit;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Audit trail")
class AuditTrailTest extends GatewayTestSupport {

    @Autowired
    JdbcTemplate jdbc;

    @Test
    @DisplayName("recorded: allowed request with client, model, tokens, cost and step latencies")
    void allowedRequest() throws Exception {
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", "hello there");
        var id = response.headers().firstValue("X-AIGate-Request-Id").orElseThrow();

        var row = awaitRow(id);

        assertThat(row).containsEntry("CLIENT_ID", "demo-agent").containsEntry("MODEL", "llama3.2:3b")
                .containsEntry("DECISION", "ALLOW").containsEntry("HTTP_STATUS", 200)
                .containsEntry("PROMPT_TOKENS", 10L).containsEntry("COMPLETION_TOKENS", 5L)
                .containsEntry("PROFILE", "balanced").containsEntry("AUTH_METHOD", "api_key");
        assertThat((Double) row.get("COST_USD")).isPositive();
        assertThat((String) row.get("STEP_MICROS")).contains("authenticate", "request_rules", "upstream");
    }

    @Test
    @DisplayName("recorded: blocked request with category and OWASP id, excerpt masked")
    void blockedRequestIsMasked() throws Exception {
        var response = chat(FINANCE_APP_KEY, "llama3.2:3b", "client PESEL 44051401359");
        var id = response.body().replaceAll("(?s).*\"audit_id\":\"([^\"]+)\".*", "$1");

        var row = awaitRow(id);

        assertThat(row).containsEntry("DECISION", "BLOCK").containsEntry("CATEGORY", "sensitive_data")
                .containsEntry("OWASP", "LLM02").containsEntry("HTTP_STATUS", 403)
                .containsEntry("RULES", "pii.pesel");
        assertThat((String) row.get("EXCERPT")).isEqualTo("client PESEL [PESEL]");
    }

    @Test
    @DisplayName("recorded: permissive client's PII reaches the model but never the audit log")
    void permissiveExcerptStillMasked() throws Exception {
        var response = chat(SANDBOX_KEY, "llama3.2:3b", "mail me at jan.kowalski@bank.pl");
        var id = response.headers().firstValue("X-AIGate-Request-Id").orElseThrow();

        assertThat((String) awaitRow(id).get("EXCERPT")).isEqualTo("mail me at [EMAIL]");
    }

    @Test
    @DisplayName("recorded: rejected API key, without a client id")
    void unauthenticated() throws Exception {
        var response = chat("wrong-key", "llama3.2:3b", "hello");
        var id = response.body().replaceAll("(?s).*\"audit_id\":\"([^\"]+)\".*", "$1");

        assertThat(awaitRow(id)).containsEntry("CATEGORY", "access_control").containsEntry("HTTP_STATUS", 401)
                .containsEntry("CLIENT_ID", null);
    }

    private Map<String, Object> awaitRow(String id) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            var rows = jdbc.queryForList("SELECT * FROM audit_event WHERE id = ?", id);
            if (!rows.isEmpty()) {
                return rows.getFirst();
            }
            Thread.sleep(50);
        }
        throw new AssertionError("no audit event " + id);
    }
}
