package pl.aibron.aigate.audit.siem;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aibron.aigate.GatewayTestSupport;
import pl.aibron.aigate.policy.PolicyStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Real UDP, TCP and HTTP receivers stand in for a syslog collector and Splunk HEC. The sinks are switched on by
 * editing the policy at runtime, the same way an operator would.
 */
@DirtiesContext
@DisplayName("SIEM forwarding: syslog CEF (UDP, TCP) and Splunk HEC")
class SiemForwardingTest extends GatewayTestSupport {

    private static final BlockingQueue<String> UDP = new LinkedBlockingQueue<>();
    private static final BlockingQueue<String> TCP = new LinkedBlockingQueue<>();
    private static final BlockingQueue<String> HEC = new LinkedBlockingQueue<>();
    private static DatagramSocket udpSocket;
    private static ServerSocket tcpSocket;
    private static HttpServer hecServer;
    private static int deadPort;

    @Autowired
    PolicyStore store;

    @DynamicPropertySource
    static void hecToken(DynamicPropertyRegistry registry) {
        registry.add("AIGATE_TEST_HEC_TOKEN", () -> "test-hec-token");
    }

    @BeforeAll
    static void startReceivers() throws Exception {
        udpSocket = new DatagramSocket(0);
        Thread.ofVirtual().start(() -> {
            var buffer = new byte[65535];
            while (!udpSocket.isClosed()) {
                var packet = new DatagramPacket(buffer, buffer.length);
                try {
                    udpSocket.receive(packet);
                    UDP.add(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8));
                } catch (IOException e) {
                    return;
                }
            }
        });
        tcpSocket = new ServerSocket(0);
        Thread.ofVirtual().start(() -> {
            while (!tcpSocket.isClosed()) {
                try {
                    var client = tcpSocket.accept();
                    Thread.ofVirtual().start(() -> {
                        try (var in = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8))) {
                            String line;
                            while ((line = in.readLine()) != null) {
                                TCP.add(line);
                            }
                        } catch (IOException ignored) {
                            // connection closed
                        }
                    });
                } catch (IOException e) {
                    return;
                }
            }
        });
        hecServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        hecServer.createContext("/services/collector/event", exchange -> {
            var body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            // Behaves like Splunk 10 HEC: a time in exponent notation is refused.
            if (body.matches("(?s).*\"time\":[0-9.]*E.*")) {
                var error = "{\"text\":\"Error in handling indexed fields\",\"code\":15}".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(400, error.length);
                exchange.getResponseBody().write(error);
            } else {
                HEC.add(exchange.getRequestHeaders().getFirst("Authorization") + " " + body);
                exchange.sendResponseHeaders(200, -1);
            }
            exchange.close();
        });
        hecServer.start();
        try (var probe = new ServerSocket(0)) {
            deadPort = probe.getLocalPort();
        }

        var policy = Files.readString(POLICY_DIR.resolve("policy.yaml"));
        Files.writeString(POLICY_DIR.resolve("policy.yaml"), policy + """

                audit:
                  sinks:
                    - type: syslog
                      name: syslog-udp
                      host: localhost
                      port: %d
                      protocol: udp
                      format: cef
                    - type: syslog
                      name: syslog-tcp-json
                      host: localhost
                      port: %d
                      protocol: tcp
                      format: json
                    - type: splunk_hec
                      name: splunk
                      url: http://localhost:%d/services/collector/event
                      token_env: AIGATE_TEST_HEC_TOKEN
                      index: aigate_test
                      sourcetype: aigate:test
                      batch_size: 3
                      batch_interval: 1s
                    - type: syslog
                      name: dead-siem
                      host: localhost
                      port: %d
                      protocol: tcp
                """.formatted(udpSocket.getLocalPort(), tcpSocket.getLocalPort(), hecServer.getAddress().getPort(),
                deadPort));
    }

    @AfterAll
    static void stopReceivers() throws Exception {
        udpSocket.close();
        tcpSocket.close();
        hecServer.stop(0);
        Files.copy(java.nio.file.Path.of("src/test/resources/policy/policy.yaml"), POLICY_DIR.resolve("policy.yaml"),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    @Test
    @DisplayName("forwarded: a blocked request reaches every SIEM, masked, while a dead SIEM delays nothing")
    void forwardsToAllSinks() throws Exception {
        awaitSinksConfigured();
        UDP.clear();
        TCP.clear();
        HEC.clear();

        long start = System.nanoTime();
        var response = chat(FINANCE_APP_KEY, "llama3.2:3b", "client PESEL 44051401359");
        long millis = (System.nanoTime() - start) / 1_000_000;

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(millis).as("client response time with one SIEM down").isLessThan(1000);

        var cef = next(UDP, "sensitive_data");
        assertThat(cef).startsWith("<164>1 ").contains("CEF:0|AIGate|", "act=BLOCK", "suser=finance-app",
                "cs1=LLM02", "cs2=pii.pesel", "msg=client PESEL [PESEL]").doesNotContain("44051401359");

        var json = next(TCP, "sensitive_data");
        assertThat(json).contains("\"decision\":\"BLOCK\"", "\"client_id\":\"finance-app\"", "\"profile\":\"strict\"",
                "\"auth_method\":\"api_key\"", "\"policy_revision\":").doesNotContain("44051401359");

        var hec = next(HEC, "sensitive_data");
        assertThat(hec).startsWith("Splunk test-hec-token ").contains("\"sourcetype\":\"aigate:test\"",
                "\"index\":\"aigate_test\"").doesNotContain("44051401359");
        assertThat(hec).containsPattern("\"time\":\\d{10}\\.\\d{3}[,}]");
    }

    @Test
    @DisplayName("batched: three quick decisions reach Splunk HEC in one request, one event object per line")
    void hecBatching() throws Exception {
        awaitSinksConfigured();
        HEC.clear();

        for (int i = 1; i <= 3; i++) {
            chat(SANDBOX_KEY, "llama3.2:3b", "batch probe " + i);
        }

        var batch = next(HEC, "batch probe 3");
        var events = batch.substring(batch.indexOf(' ', "Splunk ".length()) + 1).split("\n");
        assertThat(events).hasSize(3);
        assertThat(events).allSatisfy(e -> assertThat(e).startsWith("{").endsWith("}").contains("batch probe"));
    }

    @Test
    @DisplayName("forwarded: policy reloads are control-plane events in the SIEM too")
    void forwardsControlPlane() throws Exception {
        awaitSinksConfigured();
        UDP.clear();
        var policy = Files.readString(POLICY_DIR.resolve("policy.yaml"));
        Files.writeString(POLICY_DIR.resolve("policy.yaml"), policy + "\n# touched by test\n");

        assertThat(next(UDP, "policy_reload")).contains("CEF:0|AIGate|", "|policy|APPLIED policy|3|");
    }

    private void awaitSinksConfigured() throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(15).toNanos();
        while (store.current().audit().sinks().isEmpty()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("audit sinks never loaded: " + store.lastReload());
            }
            Thread.sleep(100);
        }
    }

    private static String next(BlockingQueue<String> queue, String containing) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            var item = queue.poll(200, TimeUnit.MILLISECONDS);
            if (item != null && item.contains(containing)) {
                return item;
            }
        }
        throw new AssertionError("nothing containing '" + containing + "' received");
    }
}
