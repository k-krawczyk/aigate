package pl.aibron.aigate.policy;

import java.util.List;

/**
 * Where audit events go besides the built-in store. Each sink is independent; a failing SIEM never blocks the
 * others or a client response.
 */
public record AuditConfig(List<SinkSpec> sinks) {

    public static final AuditConfig NONE = new AuditConfig(List.of());

    public enum SinkType { SYSLOG, SPLUNK_HEC, KAFKA }

    /** Kafka record key: keeps one client's events ordered on one partition by default. */
    public enum KafkaKey { CLIENT_ID, EVENT_TYPE, NONE }

    public enum Protocol { UDP, TCP }

    /** cef for syslog SIEMs; json is flat AIGate fields; ecs nests them as Elastic Common Schema. */
    public enum Format { CEF, JSON, ECS }

    /**
     * @param tokenEnv name of the environment variable holding the Splunk HEC token; secrets stay out of the policy
     * @param saslPasswordEnv name of the environment variable holding the Kafka SASL password, same reason
     * @param index Splunk index; omitted, the HEC token's default index applies
     * @param batchSize Splunk HEC: events per request (default 50)
     * @param batchInterval Splunk HEC: longest time an event waits for its batch (default 1s)
     */
    public record SinkSpec(SinkType type, String name, Boolean enabled, String host, Integer port, Protocol protocol,
                           Format format, String url, String tokenEnv, String bootstrapServers, String topic,
                           KafkaKey key, String securityProtocol, String saslMechanism, String saslUsername,
                           String saslPasswordEnv, String index, String sourcetype, Integer batchSize,
                           String batchInterval) {

        public boolean isEnabled() {
            return enabled == null || enabled;
        }

        public int effectiveBatchSize() {
            return batchSize == null ? 50 : batchSize;
        }

        public String effectiveBatchInterval() {
            return batchInterval == null ? "1s" : batchInterval;
        }

        public String label() {
            return name != null ? name : type.name().toLowerCase();
        }
    }

    public AuditConfig {
        sinks = sinks == null ? List.of() : List.copyOf(sinks);
    }
}
