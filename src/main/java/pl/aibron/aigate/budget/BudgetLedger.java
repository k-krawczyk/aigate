package pl.aibron.aigate.budget;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/**
 * Sliding-window consumption per client: tokens, cost and model time. A request is admitted while the client is
 * under every limit and charged afterwards from the model's own usage numbers, so one request can overshoot a
 * limit by at most its own size.
 *
 * <p>In memory, so it covers one gateway instance; a shared store (Redis) is the path to several instances.
 */
@Component
public class BudgetLedger {

    public record Charge(Instant at, long tokens, double costUsd, long modelMillis) { }

    public record Usage(long tokens, double costUsd, double modelSeconds, int requests) {
        public static final Usage NONE = new Usage(0, 0, 0, 0);
    }

    private final Map<String, Deque<Charge>> charges = new ConcurrentHashMap<>();

    public void charge(String clientId, Charge charge) {
        var deque = charges.computeIfAbsent(clientId, id -> new ArrayDeque<>());
        synchronized (deque) {
            deque.addLast(charge);
        }
    }

    public Usage usage(String clientId, Duration window) {
        var deque = charges.get(clientId);
        if (deque == null) {
            return Usage.NONE;
        }
        var since = Instant.now().minus(window);
        long tokens = 0;
        double cost = 0;
        long millis = 0;
        int requests = 0;
        synchronized (deque) {
            while (!deque.isEmpty() && deque.peekFirst().at().isBefore(since)) {
                deque.removeFirst();
            }
            for (var c : deque) {
                tokens += c.tokens();
                cost += c.costUsd();
                millis += c.modelMillis();
                requests++;
            }
        }
        return new Usage(tokens, cost, millis / 1000.0, requests);
    }

    public java.util.Set<String> clients() {
        return charges.keySet();
    }
}
