package pl.aibron.aigate.audit.siem;

import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import io.micrometer.core.instrument.MeterRegistry;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.test.EmbeddedKafkaKraftBroker;
import org.springframework.test.annotation.DirtiesContext;

import pl.aibron.aigate.GatewayTestSupport;
import pl.aibron.aigate.policy.AuditConfig.SinkType;
import pl.aibron.aigate.policy.PolicyStore;

import static org.assertj.core.api.Assertions.assertThat;

/** An embedded KRaft broker plays the bank's log bus; no Docker needed. */
@DirtiesContext
@DisplayName("SIEM forwarding: native Kafka sink")
class KafkaSinkTest extends GatewayTestSupport {

    private static final String TOPIC = "aigate.audit";
    private static EmbeddedKafkaKraftBroker broker;

    @Autowired
    PolicyStore store;

    @Autowired
    MeterRegistry metrics;

    @BeforeAll
    static void startBroker() throws Exception {
        broker = new EmbeddedKafkaKraftBroker(1, 3, TOPIC);
        broker.afterPropertiesSet();
        int deadPort;
        try (var probe = new ServerSocket(0)) {
            deadPort = probe.getLocalPort();
        }
        var policy = Files.readString(POLICY_DIR.resolve("policy.yaml"));
        Files.writeString(POLICY_DIR.resolve("policy.yaml"), policy + """

                audit:
                  sinks:
                    - type: kafka
                      name: log-bus
                      bootstrap_servers: %s
                      topic: %s
                    - type: kafka
                      name: dead-bus
                      bootstrap_servers: localhost:%d
                      topic: %s
                """.formatted(broker.getBrokersAsString(), TOPIC, deadPort, TOPIC));
    }

    @AfterAll
    static void stopBroker() throws Exception {
        broker.destroy();
        Files.copy(Path.of("src/test/resources/policy/policy.yaml"), POLICY_DIR.resolve("policy.yaml"),
                StandardCopyOption.REPLACE_EXISTING);
    }

    @Test
    @DisplayName("forwarded: masked events land on the topic keyed by client; a dead broker delays no client")
    void publishes() throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (store.current().audit().sinks().stream().noneMatch(s -> s.type() == SinkType.KAFKA)) {
            assertThat(System.nanoTime()).as("kafka sink never loaded: %s", store.lastReload()).isLessThan(deadline);
            Thread.sleep(100);
        }

        long start = System.nanoTime();
        var blocked = chat(FINANCE_APP_KEY, "llama3.2:3b", "client PESEL 44051401359");
        var allowed = chat(SANDBOX_KEY, "llama3.2:3b", "kafka sink check");
        long millis = (System.nanoTime() - start) / 1_000_000;

        assertThat(blocked.statusCode()).isEqualTo(403);
        assertThat(allowed.statusCode()).isEqualTo(200);
        assertThat(millis).as("two requests with one Kafka broker down").isLessThan(1000);

        var records = consume(record -> record.value().contains("kafka sink check")
                || record.value().contains("sensitive_data"), 2);
        assertThat(records).extracting(ConsumerRecord::key).containsExactlyInAnyOrder("finance-app", "sandbox");
        assertThat(records).allSatisfy(r -> assertThat(r.value()).doesNotContain("44051401359"));
        assertThat(records).anySatisfy(r -> assertThat(r.value())
                .contains("\"decision\":\"BLOCK\"", "\"profile\":\"strict\"", "[PESEL]"));

        long failuresDeadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (metrics.find("aigate.audit.sink.failures").tag("sink", "dead-bus").counter() == null) {
            assertThat(System.nanoTime()).as("dead broker never reported as a sink failure").isLessThan(failuresDeadline);
            Thread.sleep(200);
        }
    }

    private static List<ConsumerRecord<String, String>> consume(java.util.function.Predicate<ConsumerRecord<String, String>> wanted,
                                                                int count) {
        var props = new Properties();
        props.putAll(Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, broker.getBrokersAsString(),
                ConsumerConfig.GROUP_ID_CONFIG, "test-" + System.nanoTime(),
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName(),
                ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName()));
        var found = new ArrayList<ConsumerRecord<String, String>>();
        try (var consumer = new KafkaConsumer<String, String>(props)) {
            consumer.subscribe(List.of(TOPIC));
            long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
            while (found.size() < count && System.nanoTime() < deadline) {
                for (var record : consumer.poll(Duration.ofMillis(500))) {
                    if (wanted.test(record)) {
                        found.add(record);
                    }
                }
            }
        }
        return found;
    }
}
