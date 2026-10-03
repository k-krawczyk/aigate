package pl.aibron.aigate.dashboard;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Read side of the audit store, shaped for the dashboard and the export. */
@Component
public class AuditQueries {

    public record Summary(long total, long allowed, long redacted, long blocked, double costUsd, long tokens) {
        public double blockedShare() {
            return total == 0 ? 0 : (double) blocked / total;
        }
    }

    public record EventRow(String id, Instant timestamp, String eventType, String clientId, String model,
                           String decision, String category, String owasp, String rules, String excerpt,
                           Integer httpStatus, Double latencyMs, String detail) { }

    public record CategoryRow(String category, String owasp, long blocked, long redacted) {
        public long total() {
            return blocked + redacted;
        }
    }

    public record ClientRow(String clientId, long requests, long blocked, long redacted, long tokens, double costUsd) { }

    public record ModelRow(String model, long requests, long tokens, double costUsd) { }

    public record Bucket(Instant start, long allowed, long redacted, long blocked, long tokens, double costUsd) { }

    public record StepLatency(String step, double p50Ms, double p95Ms, long samples) { }

    public record RuleRow(String rule, long hits) { }

    private static final ObjectMapper JSON = new ObjectMapper();

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
                       COALESCE(SUM(COALESCE(prompt_tokens, 0) + COALESCE(completion_tokens, 0)), 0) AS tokens
                FROM audit_event WHERE event_type = 'chat' AND ts >= ?
                """, (rs, i) -> new Summary(rs.getLong("total"), rs.getLong("allowed"), rs.getLong("redacted"),
                rs.getLong("blocked"), rs.getDouble("cost"), rs.getLong("tokens")), Timestamp.from(since));
    }

    public List<EventRow> recent(int limit, String decision) {
        var sql = "SELECT id, ts, event_type, client_id, model, decision, category, owasp, rules, excerpt, "
                + "http_status, latency_ms, detail FROM audit_event "
                + (decision == null ? "" : "WHERE decision = ? ") + "ORDER BY ts DESC LIMIT ?";
        Object[] args = decision == null ? new Object[] {limit} : new Object[] {decision, limit};
        return jdbc.query(sql, (rs, i) -> new EventRow(rs.getString("id"), rs.getTimestamp("ts").toInstant(),
                rs.getString("event_type"), rs.getString("client_id"), rs.getString("model"),
                rs.getString("decision"), rs.getString("category"), rs.getString("owasp"), rs.getString("rules"),
                rs.getString("excerpt"), (Integer) rs.getObject("http_status"), (Double) rs.getObject("latency_ms"),
                rs.getString("detail")), args);
    }

    public List<EventRow> controlEvents(int limit) {
        return jdbc.query("""
                SELECT id, ts, event_type, decision, detail, policy_revision FROM audit_event
                WHERE event_type <> 'chat' ORDER BY ts DESC LIMIT ?
                """, (rs, i) -> new EventRow(rs.getString("id"), rs.getTimestamp("ts").toInstant(),
                rs.getString("event_type"), null, null, rs.getString("decision"), null, null, null, null, null, null,
                rs.getString("detail")), limit);
    }

    public List<CategoryRow> categories(Instant since) {
        return jdbc.query("""
                SELECT category, MAX(owasp) AS owasp,
                       COUNT(CASE WHEN decision = 'BLOCK' THEN 1 END) AS blocked,
                       COUNT(CASE WHEN decision = 'REDACT' THEN 1 END) AS redacted
                FROM audit_event
                WHERE event_type = 'chat' AND ts >= ? AND decision IN ('BLOCK', 'REDACT') AND category IS NOT NULL
                GROUP BY category ORDER BY COUNT(*) DESC
                """, (rs, i) -> new CategoryRow(rs.getString("category"), rs.getString("owasp"),
                rs.getLong("blocked"), rs.getLong("redacted")), Timestamp.from(since));
    }

    public List<ClientRow> clients(Instant since) {
        return jdbc.query("""
                SELECT client_id, COUNT(*) AS requests,
                       COUNT(CASE WHEN decision = 'BLOCK' THEN 1 END) AS blocked,
                       COUNT(CASE WHEN decision = 'REDACT' THEN 1 END) AS redacted,
                       COALESCE(SUM(COALESCE(prompt_tokens, 0) + COALESCE(completion_tokens, 0)), 0) AS tokens,
                       COALESCE(SUM(cost_usd), 0) AS cost
                FROM audit_event WHERE event_type = 'chat' AND ts >= ? AND client_id IS NOT NULL
                GROUP BY client_id ORDER BY cost DESC, requests DESC
                """, (rs, i) -> new ClientRow(rs.getString("client_id"), rs.getLong("requests"),
                rs.getLong("blocked"), rs.getLong("redacted"), rs.getLong("tokens"), rs.getDouble("cost")),
                Timestamp.from(since));
    }

    public List<ModelRow> models(Instant since) {
        return jdbc.query("""
                SELECT model, COUNT(*) AS requests,
                       COALESCE(SUM(COALESCE(prompt_tokens, 0) + COALESCE(completion_tokens, 0)), 0) AS tokens,
                       COALESCE(SUM(cost_usd), 0) AS cost
                FROM audit_event WHERE event_type = 'chat' AND ts >= ? AND model IS NOT NULL
                GROUP BY model ORDER BY tokens DESC
                """, (rs, i) -> new ModelRow(rs.getString("model"), rs.getLong("requests"), rs.getLong("tokens"),
                rs.getDouble("cost")), Timestamp.from(since));
    }

    public List<RuleRow> topRules(Instant since, int limit) {
        var counts = new HashMap<String, Long>();
        jdbc.query("SELECT rules FROM audit_event WHERE event_type = 'chat' AND ts >= ? AND rules IS NOT NULL",
                rs -> {
                    for (var rule : rs.getString("rules").split(",")) {
                        counts.merge(rule, 1L, Long::sum);
                    }
                }, Timestamp.from(since));
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(limit)
                .map(e -> new RuleRow(e.getKey(), e.getValue()))
                .toList();
    }

    /** Fixed-width time buckets, including empty ones, so a quiet period shows as a gap and not as missing data. */
    public List<Bucket> timeline(Instant since, Duration width) {
        long w = width.toMillis();
        var buckets = new TreeMap<Long, long[]>();
        var costs = new HashMap<Long, Double>();
        long first = since.toEpochMilli() / w * w;
        for (long t = first; t <= Instant.now().toEpochMilli(); t += w) {
            buckets.put(t, new long[4]);
        }
        jdbc.query("""
                SELECT ts, decision, COALESCE(prompt_tokens, 0) + COALESCE(completion_tokens, 0) AS tokens,
                       COALESCE(cost_usd, 0) AS cost
                FROM audit_event WHERE event_type = 'chat' AND ts >= ?
                """, rs -> {
            long key = rs.getTimestamp("ts").getTime() / w * w;
            var b = buckets.computeIfAbsent(key, k -> new long[4]);
            switch (String.valueOf(rs.getString("decision"))) {
                case "BLOCK" -> b[2]++;
                case "REDACT" -> b[1]++;
                default -> b[0]++;
            }
            b[3] += rs.getLong("tokens");
            costs.merge(key, rs.getDouble("cost"), Double::sum);
        }, Timestamp.from(since));
        var result = new ArrayList<Bucket>();
        buckets.forEach((t, b) -> result.add(new Bucket(Instant.ofEpochMilli(t), b[0], b[1], b[2], b[3],
                costs.getOrDefault(t, 0.0))));
        return result;
    }

    /** Per-step latency over the most recent requests, from the timings stored with each audit event. */
    public List<StepLatency> stepLatency(int sampleSize) {
        var samples = new LinkedHashMap<String, List<Long>>();
        jdbc.query("""
                SELECT step_micros FROM audit_event
                WHERE event_type = 'chat' AND step_micros IS NOT NULL ORDER BY ts DESC LIMIT ?
                """, rs -> {
            try {
                Map<String, Long> steps = JSON.readValue(rs.getString("step_micros"), new TypeReference<>() { });
                steps.forEach((step, micros) -> samples.computeIfAbsent(step, s -> new ArrayList<>()).add(micros));
            } catch (Exception e) {
                // A malformed row is skipped; the rest still gives a valid percentile.
            }
        }, sampleSize);
        var result = new ArrayList<StepLatency>();
        samples.forEach((step, values) -> {
            values.sort(Long::compare);
            result.add(new StepLatency(step, percentile(values, 0.5) / 1000.0, percentile(values, 0.95) / 1000.0,
                    values.size()));
        });
        return result;
    }

    /** Raw rows for export, oldest first so the file reads as a timeline. */
    public List<Map<String, Object>> allSince(Instant since) {
        return jdbc.queryForList("SELECT * FROM audit_event WHERE ts >= ? ORDER BY ts", Timestamp.from(since));
    }

    public Map<String, Object> byId(String id) {
        var rows = jdbc.queryForList("SELECT * FROM audit_event WHERE id = ?", id);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private static long percentile(List<Long> sorted, double p) {
        int index = (int) Math.ceil(p * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, index)));
    }
}
