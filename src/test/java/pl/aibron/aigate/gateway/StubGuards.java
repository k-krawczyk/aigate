package pl.aibron.aigate.gateway;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Stands in for the two guard models, answering in their real format including logprobs (shape copied from
 * Ollama 0.34). Flags "pipe bomb" as harmful (S9), "DAN" and "previous instructions" as injection; the tool-data
 * judges flag "aigate-test-tool-injection", which no rule knows, so tests can reach the semantic path. Fails on
 * "@guard-down" to exercise the fail-closed path.
 */
@TestConfiguration
public class StubGuards {

    public static final AtomicInteger CALLS = new AtomicInteger();

    private static final ObjectMapper JSON = new ObjectMapper();

    @Bean
    RouteBuilder stubGuardRoute() {
        return new RouteBuilder() {
            @Override
            public void configure() {
                from("direct:stub-guard").routeId("stub-guard")
                        .process(exchange -> exchange.getMessage()
                                .setBody(answer(exchange.getMessage().getBody(String.class))));
            }
        };
    }

    static String answer(String requestJson) throws Exception {
        CALLS.incrementAndGet();
        var request = JSON.readTree(requestJson);
        var messages = request.path("messages");
        var text = messages.get(messages.size() - 1).path("content").asText().toLowerCase(Locale.ROOT);
        if (text.contains("@guard-down")) {
            throw new IllegalStateException("guard model unavailable");
        }
        boolean injectionGuard = request.path("model").asText().contains("granite");
        String token;
        String other;
        String content;
        var system = messages.get(0).path("content").asText("");
        boolean toolJudge = system.contains("returned by a tool") || system.contains("tool definitions");
        if (injectionGuard && toolJudge) {
            boolean flagged = text.contains("aigate-test-tool-injection");
            token = flagged ? "Yes" : "No";
            other = flagged ? "No" : "Yes";
            content = token;
        } else if (injectionGuard) {
            boolean flagged = text.contains("dan") || text.contains("previous instructions");
            token = flagged ? "Yes" : "No";
            other = flagged ? "No" : "Yes";
            content = token;
        } else {
            boolean flagged = text.contains("pipe bomb");
            token = flagged ? "unsafe" : "safe";
            other = flagged ? "safe" : "unsafe";
            content = flagged ? "unsafe\nS9" : "safe";
        }
        var response = JSON.createObjectNode();
        var choice = response.putArray("choices").addObject();
        choice.putObject("message").put("role", "assistant").put("content", content);
        var first = choice.putObject("logprobs").putArray("content").addObject()
                .put("token", token).put("logprob", Math.log(0.98));
        first.putArray("top_logprobs")
                .add(JSON.createObjectNode().put("token", token).put("logprob", Math.log(0.98)))
                .add(JSON.createObjectNode().put("token", other).put("logprob", Math.log(0.02)));
        return response.toString();
    }
}
