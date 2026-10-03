package pl.aibron.aigate.budget;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** No Docker needed: the Redis address is one nothing answers on. */
@DisplayName("Budgets in Redis: an unreachable Redis never makes requests slow")
class RedisOutageTest {

    private static final Duration WINDOW = Duration.ofHours(1);
    // TEST-NET-1 (RFC 5737): never routed, so a connection attempt hangs until its timeout.
    private static final String BLACK_HOLE = "redis://192.0.2.1:6379";

    @Test
    @DisplayName("first call fails within the connect timeout, later calls during the backoff fail at once")
    void failsFast() {
        var ledger = new RedisBudgetLedger(BLACK_HOLE, "o1:", new SimpleMeterRegistry());

        long first = millis(() -> assertThatThrownBy(() -> ledger.usage("c", WINDOW))
                .isInstanceOf(BudgetStoreUnavailableException.class));
        long second = millis(() -> assertThatThrownBy(() -> ledger.usage("c", WINDOW))
                .isInstanceOf(BudgetStoreUnavailableException.class));
        long charge = millis(() -> ledger.charge("c", new BudgetLedger.Charge(Instant.now(), 1, 0, 0), WINDOW));

        assertThat(first).isLessThan(1500);
        assertThat(second).isLessThan(100);
        assertThat(charge).isLessThan(100);
        ledger.close();
    }

    @Test
    @DisplayName("fifty concurrent requests do not queue behind one connection attempt")
    void concurrentCallsDoNotQueue() throws Exception {
        var ledger = new RedisBudgetLedger(BLACK_HOLE, "o2:", new SimpleMeterRegistry());
        long start = System.nanoTime();
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var calls = new ArrayList<Future<?>>();
            for (int i = 0; i < 50; i++) {
                calls.add(pool.submit(() -> {
                    try {
                        ledger.usage("c", WINDOW);
                    } catch (BudgetStoreUnavailableException expected) {
                        // every call is expected to fail; the point is how fast
                    }
                }));
            }
            for (var call : calls) {
                call.get();
            }
        }
        assertThat((System.nanoTime() - start) / 1_000_000).isLessThan(1500);
        ledger.close();
    }

    private static long millis(Runnable action) {
        long start = System.nanoTime();
        action.run();
        return (System.nanoTime() - start) / 1_000_000;
    }
}
