package pl.aibron.aigate.budget;

import java.time.Duration;
import java.time.Instant;

/**
 * Sliding-window consumption per client: tokens, cost and model time. A request is admitted while the client is
 * under every limit and charged afterwards from the model's own usage numbers, so one request can overshoot a
 * limit by at most its own size.
 *
 * <p>Two stores: in memory for a single gateway, Redis when several gateway instances must share one budget
 * ({@code AIGATE_BUDGET_STORE=redis}).
 */
public interface BudgetLedger {

    record Charge(Instant at, long tokens, double costUsd, long modelMillis) { }

    record Usage(long tokens, double costUsd, double modelSeconds, int requests) {
        public static final Usage NONE = new Usage(0, 0, 0, 0);
    }

    /** {@code window} is the client's budget window; the store may drop the charge once it has passed. */
    void charge(String clientId, Charge charge, Duration window);

    Usage usage(String clientId, Duration window);
}
