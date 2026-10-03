package pl.aibron.aigate.dashboard;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Read side of the audit store, shaped for the dashboard and the export. */
@Component
public class AuditQueries {

    public record Summary(long total, long allowed, long redacted, long blocked, double costUsd, long tokens) { }

    public record EventRow(String id, Instant timestamp, String eventType, String clientId, String model,
                           String decision, String category, String owasp, String rules, String excerpt,
                           Integer httpStatus, Double latencyMs, String detail) { }

    private final JdbcTemplate jdbc;

    public AuditQueries(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Summary summarySince(Instant since) {
        return jdbc.queryForObject("""
                SELECT COUNT(*) AS total,
                       COUNT(CASE WHEN decision = 'ALLOW' THEN 1 END) AS allowed,
                       COUNT(CASE WHEN decision = 'REDACT' THEN 1 END) AS redacted,
                       COUNT(CASE WHEN decision = 'BLOCK' THEN 1 END) AS blocked,
                       COALESCE(SUM(cost_usd), 0) AS cost,
                       COALESCE(SUM(prompt_tokens + completion_tokens), 0) AS tokens
                FROM audit_event WHERE event_type = 'chat' AND ts >= ?
                """, (rs, i) -> new Summary(rs.getLong("total"), rs.getLong("allowed"), rs.getLong("redacted"),
                rs.getLong("blocked"), rs.getDouble("cost"), rs.getLong("tokens")), Timestamp.from(since));
    }

    public List<EventRow> recent(int limit) {
        return jdbc.query("""
                SELECT id, ts, event_type, client_id, model, decision, category, owasp, rules, excerpt,
                       http_status, latency_ms, detail
                FROM audit_event ORDER BY ts DESC LIMIT ?
                """, (rs, i) -> new EventRow(rs.getString("id"), rs.getTimestamp("ts").toInstant(),
                rs.getString("event_type"), rs.getString("client_id"), rs.getString("model"),
                rs.getString("decision"), rs.getString("category"), rs.getString("owasp"), rs.getString("rules"),
                rs.getString("excerpt"), (Integer) rs.getObject("http_status"), (Double) rs.getObject("latency_ms"),
                rs.getString("detail")), limit);
    }

    /** Raw rows for export, oldest first so the file reads as a timeline. */
    public List<Map<String, Object>> allSince(Instant since) {
        return jdbc.queryForList("SELECT * FROM audit_event WHERE ts >= ? ORDER BY ts", Timestamp.from(since));
    }
}
