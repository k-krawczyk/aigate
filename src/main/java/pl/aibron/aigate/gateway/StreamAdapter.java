package pl.aibron.aigate.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;

/**
 * Output checks need the whole answer, so the gateway always calls the model with stream=false. Clients that asked
 * for a stream get the checked answer as one server-sent-events chunk followed by [DONE], which every
 * OpenAI-compatible SDK accepts as a (short) stream.
 */
public final class StreamAdapter {

    private static final ObjectMapper JSON = new ObjectMapper();

    private StreamAdapter() {
    }

    /** Remembers that the client wants a stream and turns streaming off for the upstream call. */
    public static void captureStreamFlag(Exchange exchange, ObjectNode request) {
        boolean stream = request.path("stream").asBoolean(false);
        exchange.setProperty(ExchangeKeys.STREAM, stream);
        if (stream) {
            request.put("stream", false);
            request.remove("stream_options");
        }
    }

    public static void toEventStream(Exchange exchange) throws Exception {
        if (!Boolean.TRUE.equals(exchange.getProperty(ExchangeKeys.STREAM, Boolean.class))) {
            return;
        }
        var status = exchange.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE, 200, Integer.class);
        if (status != 200) {
            return;
        }
        var completion = JSON.readTree(exchange.getMessage().getBody(String.class));
        var chunk = JSON.createObjectNode();
        chunk.put("id", completion.path("id").asText());
        chunk.put("object", "chat.completion.chunk");
        chunk.put("created", completion.path("created").asLong());
        chunk.put("model", completion.path("model").asText());
        var choices = chunk.putArray("choices");
        for (JsonNode choice : completion.path("choices")) {
            var out = choices.addObject().put("index", choice.path("index").asInt());
            var message = choice.path("message");
            var delta = out.putObject("delta").put("role", "assistant");
            if (message.hasNonNull("content")) {
                delta.put("content", message.path("content").asText());
            }
            if (message.path("tool_calls").isArray()) {
                var calls = delta.putArray("tool_calls");
                int i = 0;
                for (JsonNode call : message.path("tool_calls")) {
                    var copy = ((ObjectNode) call.deepCopy()).put("index", i++);
                    calls.add(copy);
                }
            }
            out.set("finish_reason", choice.path("finish_reason"));
        }
        if (completion.has("usage")) {
            chunk.set("usage", completion.path("usage"));
        }
        exchange.getMessage().setBody("data: " + chunk + "\n\ndata: [DONE]\n\n");
        exchange.getMessage().setHeader(Exchange.CONTENT_TYPE, "text/event-stream");
    }
}
