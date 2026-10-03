package pl.aibron.aigate.audit.siem;

import java.util.LinkedHashMap;
import java.util.Map;

import pl.aibron.aigate.audit.AuditEvent;

/**
 * Elastic Common Schema view of an audit event, for sinks that feed Elasticsearch or any ECS-aware pipeline
 * directly. The flat AIGate fields stay under {@code aigate.*}, so searches written for the flat JSON keep working.
 */
public final class EcsFormatter {

    private EcsFormatter() {
    }

    public static Map<String, Object> ecs(AuditEvent e, Map<String, Object> flat) {
        var event = new LinkedHashMap<String, Object>();
        event.put("id", e.id());
        event.put("kind", "event");
        event.put("dataset", "aigate.audit");
        event.put("module", "aigate");
        event.put("action", e.eventType());
        event.put("outcome", outcome(e.decision()));
        if (e.latencyMs() != null) {
            event.put("duration", Math.round(e.latencyMs() * 1_000_000));
        }

        var doc = new LinkedHashMap<String, Object>();
        doc.put("@timestamp", e.timestamp().toString());
        doc.put("event", event);
        if (e.onBehalfOf() != null) {
            doc.put("user", Map.of("name", e.onBehalfOf()));
        }
        if (e.rules() != null || e.owasp() != null) {
            var rule = new LinkedHashMap<String, Object>();
            rule.put("name", e.rules());
            rule.put("category", e.owasp());
            doc.put("rule", rule);
        }
        if (e.httpStatus() != null) {
            doc.put("http", Map.of("response", Map.of("status_code", e.httpStatus())));
        }
        if (e.excerpt() != null) {
            doc.put("message", e.excerpt());
        }
        doc.put("aigate", flat);
        return doc;
    }

    static String outcome(String decision) {
        if (decision == null) {
            return "unknown";
        }
        return "BLOCK".equals(decision) || "REJECTED".equals(decision) ? "failure" : "success";
    }
}
