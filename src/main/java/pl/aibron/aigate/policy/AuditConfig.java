package pl.aibron.aigate.policy;

import java.util.List;

/**
 * Where audit events go besides the built-in store. Each sink is independent; a failing SIEM never blocks the
 * others or a client response.
 */
public record AuditConfig(List<SinkSpec> sinks) {

    public static final AuditConfig NONE = new AuditConfig(List.of());

    public enum SinkType { SYSLOG, SPLUNK_HEC }

    public enum Protocol { UDP, TCP }

    public enum Format { CEF, JSON }

    /**
     * @param tokenEnv name of the environment variable holding the Splunk HEC token; secrets stay out of the policy
     */
    public record SinkSpec(SinkType type, String name, Boolean enabled, String host, Integer port, Protocol protocol,
                           Format format, String url, String tokenEnv) {

        public boolean isEnabled() {
            return enabled == null || enabled;
        }

        public String label() {
            return name != null ? name : type.name().toLowerCase();
        }
    }

    public AuditConfig {
        sinks = sinks == null ? List.of() : List.copyOf(sinks);
    }
}
