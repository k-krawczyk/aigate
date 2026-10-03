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

import pl.aibron.aigate.inspection.Finding;
import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.signatures.SignatureDetector;
import pl.aibron.aigate.policy.ClientSpec.ToolPolicy;

/**
 * Excessive agency controls: which tools a client may expose to the model, and which tool calls the model may make.
 */
@Component
public class ToolGovernance {

    public record Violation(Finding finding, String message) { }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final Map<String, Pattern> compiled = new ConcurrentHashMap<>();
    private final SignatureDetector signatures;

    public ToolGovernance(SignatureDetector signatures) {
        this.signatures = signatures;
    }

    /** Tools the client offers in the request, and tool calls replayed in the conversation history. */
    public Optional<Violation> checkRequest(ObjectNode request, ToolPolicy policy) {
        for (JsonNode tool : request.path("tools")) {
            var name = tool.path("function").path("name").asText(tool.path("name").asText(""));
            if (!policy.allowed().contains(name)) {
                return Optional.of(violation(FindingKind.TOOL, "tool.not_allowed",
                        "Tool '" + name + "' is not allowed for this client"));
            }
            // A poisoned tool description is an instruction to the model hidden from the user.
            var description = tool.path("function").path("description").asText("");
            var poisoned = signatures.scan(description);
            if (!poisoned.isEmpty()) {
                return Optional.of(new Violation(poisoned.getFirst(),
                        "Description of tool '" + name + "' matches known attack " + poisoned.getFirst().label()));
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
                return Optional.of(violation(FindingKind.TOOL, "tool.not_allowed",
                        "Tool call '" + name + "' is not allowed for this client"));
            }
            var arguments = argumentTexts(function.get("arguments"));
            for (var pattern : policy.denyArgumentPatterns()) {
                var regex = compiled.computeIfAbsent(pattern, Pattern::compile);
                if (arguments.stream().anyMatch(a -> regex.matcher(a).find())) {
                    return Optional.of(violation(FindingKind.TOOL_ARGUMENT, "tool.denied_argument",
                            "Arguments of tool call '" + name + "' match a denied pattern"));
                }
            }
            for (var argument : arguments) {
                var known = signatures.scan(argument);
                if (!known.isEmpty()) {
                    return Optional.of(new Violation(known.getFirst(),
                            "Arguments of tool call '" + name + "' match known attack " + known.getFirst().label()));
                }
            }
        }
        return Optional.empty();
    }

    private static Violation violation(FindingKind kind, String rule, String message) {
        return new Violation(new Finding(rule, kind, kind.category(), 0, 0), message);
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
