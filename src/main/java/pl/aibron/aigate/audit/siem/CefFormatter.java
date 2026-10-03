package pl.aibron.aigate.audit.siem;

import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

import pl.aibron.aigate.audit.AuditEvent;

/**
 * ArcSight Common Event Format, wrapped in an RFC 5424 syslog line. QRadar, ArcSight, Microsoft Sentinel (via
 * the AMA CEF connector) and most other SIEMs parse it without a custom parser.
 */
public final class CefFormatter {

    private static final int FACILITY_LOCAL4 = 20;
    private static final String VENDOR = "AIGate";
    private static final String PRODUCT = "AI Control Layer";
    private static final String VERSION = "0.1";

    private CefFormatter() {
    }

    public static String syslogLine(AuditEvent e, String hostname) {
        int pri = FACILITY_LOCAL4 * 8 + syslogSeverity(e.decision());
        return "<" + pri + ">1 " + DateTimeFormatter.ISO_INSTANT.format(e.timestamp()) + " " + hostname
                + " aigate - " + e.eventType() + " - " + cef(e);
    }

    public static String cef(AuditEvent e) {
        var signatureId = e.category() != null ? e.category() : e.eventType();
        var name = e.decision() + (e.category() == null ? "" : " " + e.category());
        var ext = new LinkedHashMap<String, Object>();
        ext.put("rt", e.timestamp().toEpochMilli());
        ext.put("externalId", e.id());
        ext.put("act", e.decision());
        ext.put("suser", e.clientId());
        ext.put("duser", e.onBehalfOf());
        custom(ext, "cs1", "owasp", e.owasp());
        custom(ext, "cs2", "rules", e.rules());
        custom(ext, "cs3", "model", e.model());
        custom(ext, "cs4", "direction", e.direction());
        custom(ext, "cn1", "latencyMs", e.latencyMs() == null ? null : Math.round(e.latencyMs()));
        custom(ext, "cn2", "tokens", e.promptTokens() == null ? null
                : e.promptTokens() + (e.completionTokens() == null ? 0 : e.completionTokens()));
        ext.put("outcome", e.httpStatus());
        // Already masked at the source; the SIEM never receives raw PII or secrets.
        ext.put("msg", e.excerpt() != null ? e.excerpt() : e.detail());
        return "CEF:0|" + header(VENDOR) + "|" + header(PRODUCT) + "|" + VERSION + "|" + header(signatureId) + "|"
                + header(name) + "|" + cefSeverity(e.decision()) + "|" + extensions(ext);
    }

    /** CEF custom fields come in pairs; a label without a value is noise in the SIEM. */
    private static void custom(Map<String, Object> ext, String key, String label, Object value) {
        if (value != null) {
            ext.put(key + "Label", label);
            ext.put(key, value);
        }
    }

    private static String extensions(Map<String, Object> ext) {
        var sb = new StringBuilder();
        ext.forEach((key, value) -> {
            if (value != null && !(value instanceof String s && s.isEmpty())) {
                if (!sb.isEmpty()) {
                    sb.append(' ');
                }
                sb.append(key).append('=').append(extensionValue(String.valueOf(value)));
            }
        });
        return sb.toString();
    }

    static String header(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("|", "\\|").replaceAll("[\\r\\n]+", " ");
    }

    static String extensionValue(String value) {
        return value.replace("\\", "\\\\").replace("=", "\\=").replace("\r\n", "\\n").replace("\n", "\\n")
                .replace("\r", "\\n");
    }

    static int cefSeverity(String decision) {
        return switch (String.valueOf(decision)) {
            case "BLOCK" -> 7;
            case "REJECTED" -> 6;
            case "REDACT" -> 5;
            case "APPLIED" -> 3;
            default -> 2;
        };
    }

    static int syslogSeverity(String decision) {
        return switch (String.valueOf(decision)) {
            case "BLOCK" -> 4;
            case "REJECTED" -> 3;
            case "REDACT", "APPLIED" -> 5;
            default -> 6;
        };
    }
}
