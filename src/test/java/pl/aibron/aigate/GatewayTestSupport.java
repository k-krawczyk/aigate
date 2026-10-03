package pl.aibron.aigate;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aibron.aigate.gateway.StubGuards;
import pl.aibron.aigate.gateway.StubUpstream;

/**
 * Boots the gateway on a random port against a stub model and a private copy of the test policy, so tests that
 * edit the policy cannot affect each other or the shipped file.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import({StubUpstream.class, StubGuards.class})
public abstract class GatewayTestSupport {

    public static final String DEMO_AGENT_KEY = "aigate-demo-agent-key";
    public static final String FINANCE_APP_KEY = "aigate-finance-app-key";
    public static final String SANDBOX_KEY = "aigate-sandbox-key";

    protected static final Path POLICY_DIR = copyTestPolicy();

    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @Value("${local.server.port}")
    protected int port;

    @DynamicPropertySource
    static void policyDir(DynamicPropertyRegistry registry) {
        registry.add("aigate.policy.dir", POLICY_DIR::toString);
        registry.add("aigate.policy.last-known-good", () -> POLICY_DIR.resolve("last-known-good.yaml").toString());
    }

    private static Path copyTestPolicy() {
        try {
            var dir = Files.createTempDirectory("aigate-policy");
            Files.copy(Path.of("src/test/resources/policy/policy.yaml"), dir.resolve("policy.yaml"),
                    StandardCopyOption.REPLACE_EXISTING);
            return dir;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    protected HttpResponse<String> chat(String apiKey, String model, String userMessage) {
        var body = """
                {"model":"%s","messages":[{"role":"user","content":%s}]}
                """.formatted(model, jsonString(userMessage));
        return post(apiKey, body);
    }

    protected HttpResponse<String> post(String apiKey, String body) {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/chat/completions"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (apiKey != null) {
            builder.header("Authorization", "Bearer " + apiKey);
        }
        try {
            return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    protected static String jsonString(String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
}
