package pl.aibron.aigate.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Stands in for Ollama so the suite runs without a model server. Echoes the last user message back.
 */
@TestConfiguration
public class StubUpstream {

    public static final String MODEL_REPLY_PREFIX = "stub reply to: ";

    @Bean
    RouteBuilder stubUpstreamRoute() {
        return new RouteBuilder() {
            @Override
            public void configure() {
                from("direct:stub-upstream").routeId("stub-upstream")
                        .setBody(exchange -> """
                                {"id":"chatcmpl-stub","object":"chat.completion","model":"llama3.2:3b",
                                 "choices":[{"index":0,"message":{"role":"assistant","content":"%s%s"},"finish_reason":"stop"}],
                                 "usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}
                                """.formatted(MODEL_REPLY_PREFIX, lastUserMessage(exchange.getMessage().getBody(String.class))));
            }
        };
    }

    private static String lastUserMessage(String requestJson) {
        try {
            var messages = new ObjectMapper().readTree(requestJson).path("messages");
            return messages.get(messages.size() - 1).path("content").asText();
        } catch (Exception e) {
            throw new IllegalStateException("stub upstream got invalid JSON", e);
        }
    }
}
