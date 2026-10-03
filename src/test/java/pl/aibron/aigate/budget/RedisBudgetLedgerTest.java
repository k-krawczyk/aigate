package pl.aibron.aigate.budget;

import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Real Redis in a container; skipped when Docker is not available, so the suite still runs offline.
 */
@EnabledIf("pl.aibron.aigate.DockerAvailable#dockerAvailable")
@DisplayName("Budgets shared across gateway instances (Redis)")
class RedisBudgetLedgerTest {

    private static final Duration WINDOW = Duration.ofHours(1);
    private static GenericContainer<?> redis;
    private static String url;

    @BeforeAll
    static void startRedis() {
        redis = new GenericContainer<>("redis:8.2-alpine").withExposedPorts(6379);
        redis.start();
        url = "redis://" + redis.getHost() + ":" + redis.getMappedPort(6379);
    }

    @AfterAll
    static void stopRedis() {
        if (redis != null) {
            redis.stop();
        }
    }

    private static RedisBudgetLedger instance(String prefix) {
        return new RedisBudgetLedger(url, prefix, new SimpleMeterRegistry());
    }

    @Test
    @DisplayName("shared: a charge made through one gateway instance counts against the budget seen by another")
    void sharedAcrossInstances() {
        var gatewayA = instance("t1:");
        var gatewayB = instance("t1:");

        gatewayA.charge("demo-agent", new BudgetLedger.Charge(Instant.now(), 120, 0.002, 800), WINDOW);
        gatewayB.charge("demo-agent", new BudgetLedger.Charge(Instant.now(), 30, 0.001, 200), WINDOW);

        var seenByA = gatewayA.usage("demo-agent", WINDOW);
        assertThat(seenByA.tokens()).isEqualTo(150);
        assertThat(seenByA.requests()).isEqualTo(2);
        assertThat(seenByA.costUsd()).isEqualTo(0.003, org.assertj.core.data.Offset.offset(1e-9));
        assertThat(seenByA.modelSeconds()).isEqualTo(1.0);
        assertThat(gatewayB.usage("demo-agent", WINDOW)).isEqualTo(seenByA);
        assertThat(gatewayB.usage("other-client", WINDOW)).isEqualTo(BudgetLedger.Usage.NONE);
        gatewayA.close();
        gatewayB.close();
    }

    @Test
    @DisplayName("sliding window: charges older than the window no longer count and are pruned")
    void slidingWindow() throws Exception {
        var ledger = instance("t2:");
        ledger.charge("c", new BudgetLedger.Charge(Instant.now().minus(Duration.ofMinutes(90)), 1000, 1, 1), WINDOW);
        ledger.charge("c", new BudgetLedger.Charge(Instant.now(), 10, 0, 1), WINDOW);

        assertThat(ledger.usage("c", WINDOW).tokens()).isEqualTo(10);
        assertThat(redis.execInContainer("redis-cli", "ZCARD", "t2:c").getStdout().trim()).isEqualTo("1");
        var ttl = Long.parseLong(redis.execInContainer("redis-cli", "PTTL", "t2:c").getStdout().trim());
        assertThat(ttl).isBetween(WINDOW.toMillis(), WINDOW.plusMinutes(1).toMillis());
        ledger.close();
    }

    @Test
    @DisplayName("outage: reads fail fast as BudgetStoreUnavailableException, writes never throw")
    void outage() throws Exception {
        int deadPort;
        try (var probe = new ServerSocket(0)) {
            deadPort = probe.getLocalPort();
        }
        var ledger = new RedisBudgetLedger("redis://localhost:" + deadPort, "t3:", new SimpleMeterRegistry());

        long start = System.nanoTime();
        assertThatThrownBy(() -> ledger.usage("c", WINDOW)).isInstanceOf(BudgetStoreUnavailableException.class);
        ledger.charge("c", new BudgetLedger.Charge(Instant.now(), 1, 0, 0), WINDOW);

        assertThat((System.nanoTime() - start) / 1_000_000).isLessThan(3000);
        ledger.close();
    }
}
