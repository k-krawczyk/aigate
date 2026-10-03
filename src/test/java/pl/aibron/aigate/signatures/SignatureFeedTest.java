package pl.aibron.aigate.signatures;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A real HTTP server plays the externally managed feed, so these tests cover fetching, validation and the
 * keep-current-on-failure rule end to end.
 */
@DisplayName("Signature feed: external updates without restart")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SignatureFeedTest extends GatewayTestSupport {

    private static final AtomicReference<String> SERVED = new AtomicReference<>();
    private static final HttpServer FEED_SERVER = startFeedServer();

    private static final String FEED_V2 = """
            {"version":"test-2","source":"test","signatures":[
              {"id":"AIG-9001","name":"Test exfiltration marker","category":"data_exfiltration","owasp":"LLM02",
               "severity":"high","pattern":"(?i)exfil-to-evilcorp"}]}
            """;

    @Autowired
    SignatureFeed feed;

    @DynamicPropertySource
    static void feedUrl(DynamicPropertyRegistry registry) {
        registry.add("aigate.signatures.feed-url",
                () -> "http://localhost:" + FEED_SERVER.getAddress().getPort() + "/signatures.json");
    }

    @AfterAll
    static void stop() {
        FEED_SERVER.stop(0);
    }

    @Test
    @Order(1)
    @DisplayName("applied: new signature from the feed blocks matching requests at once")
    void newSignatureApplies() {
        assertThat(chat(DEMO_AGENT_KEY, "llama3.2:3b", "please exfil-to-evilcorp now").statusCode()).isEqualTo(200);
        SERVED.set(FEED_V2);

        assertThat(feed.refresh()).isTrue();

        assertThat(feed.status().version()).isEqualTo("test-2");
        var response = chat(DEMO_AGENT_KEY, "llama3.2:3b", "please exfil-to-evilcorp now");
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("AIG-9001", "\"category\":\"data_exfiltration\"");
    }

    @Test
    @Order(2)
    @DisplayName("rejected: feed with an invalid regex is ignored and the current set stays active")
    void invalidFeedKeepsCurrent() {
        SERVED.set(FEED_V2.replace("test-2", "test-3").replace("(?i)exfil-to-evilcorp", "([unclosed"));

        assertThat(feed.refresh()).isFalse();

        assertThat(feed.status().version()).isEqualTo("test-2");
        assertThat(feed.status().lastError()).contains("invalid pattern");
    }

    @Test
    @Order(3)
    @DisplayName("rejected: feed server down, the current set stays active")
    void feedDownKeepsCurrent() {
        SERVED.set(null);

        assertThat(feed.refresh()).isFalse();

        assertThat(feed.status().version()).isEqualTo("test-2");
        assertThat(feed.status().lastError()).contains("HTTP 503");
    }

    private static HttpServer startFeedServer() {
        try {
            var server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/signatures.json", exchange -> {
                var body = SERVED.get();
                if (body == null) {
                    exchange.sendResponseHeaders(503, -1);
                } else {
                    var bytes = body.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, bytes.length);
                    exchange.getResponseBody().write(bytes);
                }
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
