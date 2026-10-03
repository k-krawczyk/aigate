package pl.aibron.aigate.gateway;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

/**
 * A piece of text inside a chat message that can be inspected and rewritten in place. Covers both content forms
 * of the OpenAI API: a plain string, and an array of parts where text parts carry {@code text}.
 */
public final class MessageText {

    private final ObjectNode holder;
    private final String field;
    private final String role;

    private MessageText(ObjectNode holder, String field, String role) {
        this.holder = holder;
        this.field = field;
        this.role = role;
    }

    public String role() {
        return role;
    }

    public String text() {
        return holder.path(field).asText("");
    }

    public void replace(String text) {
        holder.set(field, TextNode.valueOf(text));
    }

    private static List<MessageText> of(Iterable<JsonNode> messages) {
        var texts = new ArrayList<MessageText>();
        for (JsonNode message : messages) {
            if (!(message instanceof ObjectNode msg)) {
                continue;
            }
            var role = msg.path("role").asText("");
            var content = msg.get("content");
            if (content != null && content.isTextual()) {
                texts.add(new MessageText(msg, "content", role));
            } else if (content instanceof ArrayNode parts) {
                for (JsonNode part : parts) {
                    if (part instanceof ObjectNode p && p.path("text").isTextual()) {
                        texts.add(new MessageText(p, "text", role));
                    }
                }
            }
        }
        return texts;
    }

    /** Text of every message in a request, for inspection. */
    public static List<MessageText> ofRequest(ObjectNode request) {
        return request.get("messages") instanceof ArrayNode messages ? of(messages) : List.of();
    }

    /** Assistant message text of every choice in a response. */
    public static List<MessageText> ofResponse(ObjectNode response) {
        var messages = new ArrayList<JsonNode>();
        response.path("choices").forEach(choice -> messages.add(choice.path("message")));
        return of(messages);
    }

    /**
     * The turn's new input: messages after the last assistant message, plus the tool calls that assistant message
     * made. Only for loop detection, where the shared history would otherwise make every chat look repetitive.
     * Never for security checks: the client writes the whole history, including "assistant" turns.
     */
    public static String newInput(ObjectNode request) {
        var messages = request.path("messages");
        int lastAssistant = -1;
        for (int i = 0; i < messages.size(); i++) {
            if ("assistant".equals(messages.get(i).path("role").asText())) {
                lastAssistant = i;
            }
        }
        var text = new StringBuilder();
        if (lastAssistant >= 0) {
            for (JsonNode call : messages.get(lastAssistant).path("tool_calls")) {
                text.append(call.path("function").toString()).append(' ');
            }
        }
        for (int i = lastAssistant + 1; i < messages.size(); i++) {
            var content = messages.get(i).path("content");
            text.append(content.isTextual() ? content.asText() : content.toString()).append(' ');
        }
        return text.toString();
    }

    /**
     * Everything in the conversation the client controls, for the injection and harm checks: every message except
     * the system prompt, including earlier "assistant" turns and tool results, because the gateway cannot tell a
     * genuine history from one the client made up.
     */
    public static String conversationInput(ObjectNode request) {
        var text = new StringBuilder();
        for (JsonNode message : request.path("messages")) {
            if ("system".equals(message.path("role").asText())) {
                continue;
            }
            var content = message.path("content");
            if (content.isTextual()) {
                text.append(content.asText()).append('\n');
            } else if (content.isArray()) {
                content.forEach(part -> text.append(part.path("text").asText("")).append('\n'));
            }
            for (JsonNode call : message.path("tool_calls")) {
                text.append(call.path("function").toString()).append('\n');
            }
        }
        return text.toString();
    }
}
