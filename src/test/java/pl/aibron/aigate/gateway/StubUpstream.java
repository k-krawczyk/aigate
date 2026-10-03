package pl.aibron.aigate.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Stands in for Ollama so the suite runs without a model server. By default it echoes the last user message, which
 * lets tests see exactly what the model received. Two commands script a misbehaving model:
 * <ul>
 *   <li>{@code @tool <name> <json-arguments>}: answer with a tool call</li>
 *   <li>{@code @say <text>}: answer with this text verbatim</li>
 *   <li>{@code @fixture <key>}: answer with text registered in {@link #FIXTURES}, for answers whose content
 *       would already be caught if it appeared in the request</li>
 *   <li>{@code @leak}: answer with the full system prompt the model received</li>
 *   <li>{@code @upstream-down}: fail as an unreachable model server would</li>
 * </ul>
 */
@TestConfiguration
public class StubUpstream {

    public static final String MODEL_REPLY_PREFIX = "stub reply to: ";

    public static final java.util.Map<String, String> FIXTURES = new java.util.concurrent.ConcurrentHashMap<>();

    private static final ObjectMapper JSON = new ObjectMapper();

    @Bean
    RouteBuilder stubUpstreamRoute() {
        return new RouteBuilder() {
            @Override
            public void configure() {
                from("direct:stub-upstream").routeId("stub-upstream")
                        .process(exchange -> exchange.getMessage()
                                .setBody(reply(exchange.getMessage().getBody(String.class))));
            }
        };
    }

    static String reply(String requestJson) throws Exception {
        var request = JSON.readTree(requestJson);
        var messages = request.path("messages");
        var last = messages.get(messages.size() - 1).path("content").asText();

        var response = JSON.createObjectNode();
        response.put("id", "chatcmpl-stub").put("object", "chat.completion").put("model", request.path("model").asText());
        var message = response.putArray("choices").addObject().put("index", 0).put("finish_reason", "stop")
                .putObject("message").put("role", "assistant");
        response.putObject("usage").put("prompt_tokens", 10).put("completion_tokens", 5).put("total_tokens", 15);

        if (last.equals("@upstream-down")) {
            throw new java.net.ConnectException("Connection refused");
        }
        if (last.startsWith("@tool ")) {
            var parts = last.substring(6).split(" ", 2);
            message.put("content", "");
            var call = message.putArray("tool_calls").addObject().put("id", "call_1").put("type", "function");
            call.putObject("function").put("name", parts[0]).put("arguments", parts.length > 1 ? parts[1] : "{}");
        } else if (last.startsWith("@fixture ")) {
            message.put("content", FIXTURES.get(last.substring(9).trim()));
        } else if (last.startsWith("@say ")) {
            message.put("content", last.substring(5));
        } else if (last.equals("@leak")) {
            message.put("content", "My instructions are: " + systemPrompt(messages));
        } else {
            message.put("content", MODEL_REPLY_PREFIX + last);
        }
        return response.toString();
    }

    private static String systemPrompt(JsonNode messages) {
        for (JsonNode m : messages) {
            if ("system".equals(m.path("role").asText())) {
                return m.path("content").asText();
            }
        }
        return "";
    }

}
