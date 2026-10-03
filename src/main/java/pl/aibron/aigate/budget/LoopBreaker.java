package pl.aibron.aigate.budget;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

/**
 * Detects runaway agents: the same new input arriving again and again in a short time.
 *
 * <p>Only the turn's new input is compared (messages after the last assistant message, plus the tool calls that
 * assistant message made). Comparing the whole conversation would flag every ordinary multi-turn chat, because the
 * shared history dominates the similarity.
 */
@Component
public class LoopBreaker {

    private record Seen(Instant at, Set<String> shingles) { }

    private final Map<String, Deque<Seen>> history = new ConcurrentHashMap<>();

    /** Records this request and returns how many earlier similar requests fall inside the window. */
    public int similarRecent(String clientId, ObjectNode request, Duration within, double similarity) {
        var current = shingles(newInput(request));
        var deque = history.computeIfAbsent(clientId, id -> new ArrayDeque<>());
        var since = Instant.now().minus(within);
        int similar = 0;
        synchronized (deque) {
            while (!deque.isEmpty() && deque.peekFirst().at().isBefore(since)) {
                deque.removeFirst();
            }
            for (var seen : deque) {
                if (jaccard(seen.shingles(), current) >= similarity) {
                    similar++;
                }
            }
            deque.addLast(new Seen(Instant.now(), current));
        }
        return similar;
    }

    static String newInput(ObjectNode request) {
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

    static Set<String> shingles(String text) {
        var words = text.toLowerCase(Locale.ROOT).replaceAll("[^\\p{L}\\p{N}\\s]", " ").trim().split("\\s+");
        var result = new HashSet<String>();
        for (int i = 0; i < words.length; i++) {
            result.add(words[i]);
            if (i + 1 < words.length) {
                result.add(words[i] + " " + words[i + 1]);
            }
        }
        return result;
    }

    static double jaccard(Set<String> a, Set<String> b) {
        if (a.isEmpty() && b.isEmpty()) {
            return 1.0;
        }
        int intersection = 0;
        for (var s : a) {
            if (b.contains(s)) {
                intersection++;
            }
        }
        return (double) intersection / (a.size() + b.size() - intersection);
    }
}
