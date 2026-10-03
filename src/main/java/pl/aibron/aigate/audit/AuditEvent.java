package pl.aibron.aigate.audit;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * One governed interaction or one control-plane change. {@code profile} is the effective profile after IdP group
 * tightening, so the SOC can see why the same agent and text were treated differently for two people. Contains masked text only: an audit log full of raw
 * secrets would be a vulnerability of its own.
 */
public record AuditEvent(
        String id,
        Instant timestamp,
        String eventType,
        String clientId,
        String subject,
        String onBehalfOf,
        String authMethod,
        String model,
        String direction,
        String decision,
        String category,
        String owasp,
        String rules,
        String excerpt,
        Integer httpStatus,
        Long promptTokens,
        Long completionTokens,
        Double costUsd,
        Double latencyMs,
        Map<String, Long> stepMicros,
        Integer policyRevision,
        String detail,
        String profile,
        List<String> groups) {

    public static final String CHAT = "chat";
    public static final String POLICY_RELOAD = "policy_reload";
    public static final String FEED_UPDATE = "signature_feed";

    public static AuditEvent feedUpdate(String version, int count, String origin) {
        return new AuditEvent(java.util.UUID.randomUUID().toString(), Instant.now(), FEED_UPDATE, null, null, null,
                null, null, null, "APPLIED", "signature_feed", null, null, null, null, null, null, null, null, null,
                null, "Signature feed " + version + " applied: " + count + " signatures from " + origin, null, null);
    }
}
