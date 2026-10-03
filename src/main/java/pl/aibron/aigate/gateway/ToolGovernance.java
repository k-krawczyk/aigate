package pl.aibron.aigate.gateway;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.policy.ClientSpec.ToolPolicy;

/**
 * Excessive agency controls: which tools a client may expose to the model, and which tool calls the model may make.
 */
@Component
public class ToolGovernance {

    public record Violation(FindingKind kind, String rule, String message) { }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final Map<String, Pattern> compiled = new ConcurrentHashMap<>();

    /** Tools the client offers in the request, and tool calls replayed in the conversation history. */
    public Optional<Violation> checkRequest(ObjectNode request, ToolPolicy policy) {
        for (JsonNode tool : request.path("tools")) {
            var name = tool.path("function").path("name").asText(tool.path("name").asText(""));
            if (!policy.allowed().contains(name)) {
                return Optional.of(new Violation(FindingKind.TOOL, "tool.not_allowed",
                        "Tool '" + name + "' is not allowed for this client"));
            }
        }
        for (JsonNode message : request.path("messages")) {
            var violation = checkCalls(message.path("tool_calls"), policy);
            if (violation.isPresent()) {
                return violation;
            }
        }
        return Optional.empty();
    }

    /** Tool calls the model wants to make. */
    public Optional<Violation> checkResponse(ObjectNode response, ToolPolicy policy) {
        for (JsonNode choice : response.path("choices")) {
            var violation = checkCalls(choice.path("message").path("tool_calls"), policy);
            if (violation.isPresent()) {
                return violation;
            }
        }
        return Optional.empty();
    }

    private Optional<Violation> checkCalls(JsonNode toolCalls, ToolPolicy policy) {
        for (JsonNode call : toolCalls) {
            var function = call.path("function");
            var name = function.path("name").asText("");
            if (!policy.allowed().contains(name)) {
                return Optional.of(new Violation(FindingKind.TOOL, "tool.not_allowed",
                        "Tool call '" + name + "' is not allowed for this client"));
            }
            var arguments = argumentTexts(function.get("arguments"));
            for (var pattern : policy.denyArgumentPatterns()) {
                var regex = compiled.computeIfAbsent(pattern, Pattern::compile);
                if (arguments.stream().anyMatch(a -> regex.matcher(a).find())) {
                    return Optional.of(new Violation(FindingKind.TOOL_ARGUMENT, "tool.denied_argument",
                            "Arguments of tool call '" + name + "' match a denied pattern"));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * The raw argument string plus every string value inside it, so escaping in the JSON encoding cannot hide a
     * denied pattern.
     */
    private static List<String> argumentTexts(JsonNode arguments) {
        var texts = new ArrayList<String>();
        if (arguments == null || arguments.isNull()) {
            return texts;
        }
        var raw = arguments.isTextual() ? arguments.asText() : arguments.toString();
        texts.add(raw);
        try {
            collectStrings(arguments.isTextual() ? JSON.readTree(raw) : arguments, texts);
        } catch (Exception e) {
            // Not JSON: the raw string is still checked.
        }
        return texts;
    }

    private static void collectStrings(JsonNode node, List<String> out) {
        if (node.isTextual()) {
            out.add(node.asText());
        }
        node.forEach(child -> collectStrings(child, out));
    }
}
