package pl.aibron.aigate.audit;

import java.sql.Timestamp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class H2AuditSink implements AuditSink {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final JdbcTemplate jdbc;

    public H2AuditSink(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public String name() {
        return "h2";
    }

    @Override
    public void publish(AuditEvent e) {
        jdbc.update("""
                INSERT INTO audit_event (id, ts, event_type, client_id, subject, on_behalf_of, auth_method, model,
                    direction, decision, category, owasp, rules, excerpt, http_status, prompt_tokens,
                    completion_tokens, cost_usd, latency_ms, step_micros, policy_revision, detail)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                e.id(), Timestamp.from(e.timestamp()), e.eventType(), e.clientId(), e.subject(), e.onBehalfOf(),
                e.authMethod(), e.model(), e.direction(), e.decision(), e.category(), e.owasp(), e.rules(),
                e.excerpt(), e.httpStatus(), e.promptTokens(), e.completionTokens(), e.costUsd(), e.latencyMs(),
                toJson(e), e.policyRevision(), e.detail());
    }

    private static String toJson(AuditEvent e) {
        try {
            return e.stepMicros() == null ? null : JSON.writeValueAsString(e.stepMicros());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
