package pl.aibron.aigate.budget;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Budget ledger for a single gateway instance. */
@Component
@ConditionalOnProperty(name = "aigate.budget.store", havingValue = "memory", matchIfMissing = true)
public class InMemoryBudgetLedger implements BudgetLedger {

    private final Map<String, Deque<Charge>> charges = new ConcurrentHashMap<>();

    @Override
    public void charge(String clientId, Charge charge, Duration window) {
        var deque = charges.computeIfAbsent(clientId, id -> new ArrayDeque<>());
        synchronized (deque) {
            deque.addLast(charge);
        }
    }

    @Override
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

}
