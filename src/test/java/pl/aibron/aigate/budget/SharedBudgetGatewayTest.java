package pl.aibron.aigate.budget;

import java.time.Duration;
import java.time.Instant;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The gateway under test uses Redis for budgets; a second ledger plays another gateway instance spending the same
 * client's budget. Skipped without Docker.
 */
@DirtiesContext
@EnabledIf("pl.aibron.aigate.DockerAvailable#dockerAvailable")
@DisplayName("Budgets shared across gateway instances: end to end")
class SharedBudgetGatewayTest extends GatewayTestSupport {

    private static GenericContainer<?> redis;

    @DynamicPropertySource
    static void redisStore(DynamicPropertyRegistry registry) {
        redis = new GenericContainer<>("redis:8.2-alpine").withExposedPorts(6379);
        redis.start();
        registry.add("aigate.budget.store", () -> "redis");
        registry.add("aigate.budget.redis-url", () -> "redis://" + redis.getHost() + ":" + redis.getMappedPort(6379));
    }

    @AfterAll
    static void stopRedis() {
        if (redis != null) {
            redis.stop();
        }
    }

    @Test
    @DisplayName("refused: the tiny-budget client's 40 tokens were already spent on another gateway instance")
    void budgetSpentElsewhere() {
        assertThat(chat("aigate-tiny-budget-key", "llama3.2:3b", "first, on this instance").statusCode())
                .isEqualTo(200);

        var otherInstance = new RedisBudgetLedger("redis://" + redis.getHost() + ":" + redis.getMappedPort(6379),
                "aigate:budget:", new SimpleMeterRegistry());
        otherInstance.charge("tiny-budget", new BudgetLedger.Charge(Instant.now(), 30, 0, 100), Duration.ofHours(1));
        otherInstance.close();

        var response = chat("aigate-tiny-budget-key", "llama3.2:3b", "second, after the other instance spent");
        assertThat(response.statusCode()).isEqualTo(429);
        assertThat(response.body()).contains("token_budget_exceeded");
    }
}
