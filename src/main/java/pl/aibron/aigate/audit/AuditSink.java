package pl.aibron.aigate.audit;

/**
 * Destination for audit events. H2 feeds the dashboard; a SIEM (syslog CEF, Splunk HEC, Kafka) is another sink.
 * Sinks are independent: one failing never stops the others or delays a client response.
 */
public interface AuditSink {

    String name();

    void publish(AuditEvent event);
}
