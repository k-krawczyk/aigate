package pl.aibron.aigate.audit.siem;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import org.apache.camel.CamelContext;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.component.kafka.KafkaConstants;
import org.apache.camel.component.kafka.KafkaEndpoint;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.policy.AuditConfig.KafkaKey;
import pl.aibron.aigate.policy.AuditConfig.SinkSpec;

/**
 * Publishes audit events to a Kafka topic through the Camel kafka component.
 *
 * <p>The producer is bounded so a broker outage cannot back up the gateway: send() blocks at most 2 s for
 * metadata, a record is given up after 10 s, and buffering is capped at 8 MB. Sends are asynchronous; the result
 * is reported to a callback that feeds the sink metrics.
 *
 * <p>The SASL password is set on the endpoint's configuration object, not in its URI, so it never appears where
 * Camel shows endpoint URIs (logs, JMX, health details).
 */
@Component
public class KafkaSender {

    private static final String PRODUCER_LIMITS =
            "&maxBlockMs=2000&requestTimeoutMs=5000&deliveryTimeoutMs=10000&lingerMs=5&bufferMemorySize=8388608"
                    + "&retries=3";

    private final CamelContext camel;
    private final ProducerTemplate producer;
    private final Environment environment;
    private final Map<String, KafkaEndpoint> endpoints = new ConcurrentHashMap<>();

    public KafkaSender(CamelContext camel, ProducerTemplate producer, Environment environment) {
        this.camel = camel;
        this.producer = producer;
        this.environment = environment;
    }

    public void send(SinkSpec spec, String clientId, String eventType, String payload, Consumer<Throwable> done) {
        var endpoint = endpoints.computeIfAbsent(uri(spec), this::createEndpoint);
        configureSecurity(spec, endpoint);
        var key = spec.key() == null ? KafkaKey.CLIENT_ID : spec.key();
        producer.asyncSend(endpoint, exchange -> {
            exchange.getMessage().setBody(payload);
            switch (key) {
                case CLIENT_ID -> exchange.getMessage().setHeader(KafkaConstants.KEY, clientId == null ? "-" : clientId);
                case EVENT_TYPE -> exchange.getMessage().setHeader(KafkaConstants.KEY, eventType);
                case NONE -> { }
            }
        }).whenComplete((exchange, error) -> done.accept(error != null ? error : exchange.getException()));
    }

    private static String uri(SinkSpec spec) {
        var uri = new StringBuilder("kafka:").append(spec.topic())
                .append("?brokers=").append(spec.bootstrapServers())
                .append("&clientId=aigate-audit-").append(spec.label())
                .append(PRODUCER_LIMITS);
        if (spec.securityProtocol() != null) {
            uri.append("&securityProtocol=").append(spec.securityProtocol());
        }
        if (spec.saslMechanism() != null) {
            uri.append("&saslMechanism=").append(spec.saslMechanism());
        }
        return uri.toString();
    }

    private KafkaEndpoint createEndpoint(String uri) {
        return camel.getEndpoint(uri, KafkaEndpoint.class);
    }

    private void configureSecurity(SinkSpec spec, KafkaEndpoint endpoint) {
        if (spec.saslMechanism() == null) {
            return;
        }
        var password = environment.getProperty(spec.saslPasswordEnv());
        if (password == null) {
            throw new IllegalStateException("environment variable " + spec.saslPasswordEnv() + " is not set");
        }
        var module = spec.saslMechanism().equals("PLAIN")
                ? "org.apache.kafka.common.security.plain.PlainLoginModule"
                : "org.apache.kafka.common.security.scram.ScramLoginModule";
        endpoint.getConfiguration().setSaslJaasConfig(module + " required username=\"" + spec.saslUsername()
                + "\" password=\"" + password.replace("\"", "\\\"") + "\";");
    }
}
