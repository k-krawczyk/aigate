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
                    completion_tokens, cost_usd, latency_ms, step_micros, policy_revision, detail, profile,
                    caller_groups)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                e.id(), Timestamp.from(e.timestamp()), cap(e.eventType(), 32), cap(e.clientId(), 256),
                cap(e.subject(), 256), cap(e.onBehalfOf(), 256), cap(e.authMethod(), 160), cap(e.model(), 128),
                cap(e.direction(), 16), cap(e.decision(), 16), cap(e.category(), 64), cap(e.owasp(), 16),
                cap(e.rules(), 2048), cap(e.excerpt(), 1024), e.httpStatus(), e.promptTokens(), e.completionTokens(),
                e.costUsd(), e.latencyMs(), cap(toJson(e), 2048), e.policyRevision(), cap(e.detail(), 4096),
                cap(e.profile(), 256), cap(e.groups() == null ? null : String.join(",", e.groups()), 4096));
    }

    /**
     * Fits a value to its column. Losing the end of a long value is better than losing the whole event, which is
     * what H2 does with a value that is too long.
     */
    static String cap(String value, int width) {
        return value == null || value.length() <= width ? value : value.substring(0, width - 3) + "...";
    }

    private static String toJson(AuditEvent e) {
        try {
            return e.stepMicros() == null ? null : JSON.writeValueAsString(e.stepMicros());
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
