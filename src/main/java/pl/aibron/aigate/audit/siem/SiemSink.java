package pl.aibron.aigate.audit.siem;

import java.math.BigDecimal;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.audit.AuditEvent;
import pl.aibron.aigate.audit.AuditSink;
import pl.aibron.aigate.policy.AuditConfig.Format;
import pl.aibron.aigate.policy.AuditConfig.SinkSpec;
import pl.aibron.aigate.policy.PolicyStore;

/**
 * Forwards audit events to the SIEM sinks configured in the policy. Each target is a Camel endpoint (netty for
 * syslog, http for Splunk HEC), so adding a SIEM is a policy edit, applied on the next event without a restart.
 */
@Component
public class SiemSink implements AuditSink {

    private static final Logger log = LoggerFactory.getLogger(SiemSink.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final PolicyStore policyStore;
    private final ProducerTemplate producer;
    private final MeterRegistry metrics;
    private final String syslogHostOverride;
    private final String hostname;

    private final Environment environment;

    public SiemSink(PolicyStore policyStore, ProducerTemplate producer, MeterRegistry metrics, Environment environment,
                    @Value("${aigate.siem.syslog-host:}") String syslogHostOverride) {
        this.policyStore = policyStore;
        this.environment = environment;
        this.producer = producer;
        this.metrics = metrics;
        this.syslogHostOverride = syslogHostOverride;
        this.hostname = localHostname();
    }

    @Override
    public String name() {
        return "siem";
    }

    @Override
    public void publish(AuditEvent event) {
        for (var spec : policyStore.current().audit().sinks()) {
            if (!spec.isEnabled()) {
                continue;
            }
            try {
                switch (spec.type()) {
                    case SYSLOG -> sendSyslog(spec, event);
                    case SPLUNK_HEC -> sendSplunk(spec, event);
                }
                metrics.counter("aigate.audit.sink.sent", "sink", spec.label()).increment();
            } catch (RuntimeException e) {
                metrics.counter("aigate.audit.sink.failures", "sink", spec.label()).increment();
                log.warn("SIEM sink {} failed for event {}: {}", spec.label(), event.id(), e.getMessage());
            }
        }
    }

    private void sendSyslog(SinkSpec spec, AuditEvent event) {
        var host = syslogHostOverride.isBlank() ? spec.host() : syslogHostOverride;
        var payload = spec.format() == Format.JSON ? toJson(event) : CefFormatter.syslogLine(event, hostname);
        if (spec.protocol() == pl.aibron.aigate.policy.AuditConfig.Protocol.TCP) {
            // RFC 6587 non-transparent framing: one event per line.
            producer.sendBody("netty:tcp://" + host + ":" + spec.port() + "?sync=false&textline=true", payload);
        } else {
            producer.sendBody("netty:udp://" + host + ":" + spec.port() + "?sync=false&udpByteArrayCodec=true",
                    payload.getBytes(StandardCharsets.UTF_8));
        }
    }

    private void sendSplunk(SinkSpec spec, AuditEvent event) {
        // Spring's Environment includes OS environment variables.
        var token = environment.getProperty(spec.tokenEnv());
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("environment variable " + spec.tokenEnv() + " is not set");
        }
        // Epoch seconds as a plain decimal. A double would be written as 1.791048401679E9, which Splunk 10 HEC
        // rejects with code 15 "Error in handling indexed fields".
        var body = JSON.createObjectNode().put("sourcetype", "aigate:audit").put("source", "aigate")
                .put("host", hostname)
                .put("time", BigDecimal.valueOf(event.timestamp().toEpochMilli()).movePointLeft(3));
        body.set("event", JSON.valueToTree(asMap(event)));
        var reply = producer.request(spec.url(), exchange -> {
            exchange.getMessage().setHeader(Exchange.HTTP_METHOD, "POST");
            exchange.getMessage().setHeader(Exchange.CONTENT_TYPE, "application/json");
            exchange.getMessage().setHeader("Authorization", "Splunk " + token);
            exchange.getMessage().setBody(body.toString());
        });
        if (reply.getException() != null) {
            throw new IllegalStateException(reply.getException().getMessage(), reply.getException());
        }
    }

    private static String toJson(AuditEvent event) {
        try {
            return JSON.writeValueAsString(asMap(event));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> asMap(AuditEvent e) {
        var m = new LinkedHashMap<String, Object>();
        m.put("id", e.id());
        m.put("timestamp", e.timestamp().toString());
        m.put("event_type", e.eventType());
        m.put("client_id", e.clientId());
        m.put("subject", e.subject());
        m.put("on_behalf_of", e.onBehalfOf());
        m.put("auth_method", e.authMethod());
        m.put("profile", e.profile());
        m.put("groups", e.groups());
        m.put("policy_revision", e.policyRevision());
        m.put("model", e.model());
        m.put("decision", e.decision());
        m.put("category", e.category());
        m.put("owasp", e.owasp());
        m.put("rules", e.rules());
        m.put("excerpt", e.excerpt());
        m.put("http_status", e.httpStatus());
        m.put("latency_ms", e.latencyMs());
        m.put("detail", e.detail());
        return m;
    }

    private static String localHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "aigate";
        }
    }
}
