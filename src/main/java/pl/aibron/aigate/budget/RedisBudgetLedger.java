package pl.aibron.aigate.budget;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import java.util.concurrent.locks.ReentrantLock;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisException;
import io.lettuce.core.RedisURI;
import io.lettuce.core.ScriptOutputType;
import io.lettuce.core.SocketOptions;
import io.lettuce.core.api.StatefulRedisConnection;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Budget ledger shared by every gateway instance through Redis.
 *
 * <p>One sorted set per client, scored by charge time, one member per charge. Pruning and reading happen in one
 * Lua script, and so do adding and refreshing the expiry, so concurrent instances never see a half-applied
 * charge. Keys expire one minute after the window, so a client that stops calling leaves nothing behind.
 *
 * <p>Commands and connection attempts time out after 300 ms, commands are rejected at once while the connection
 * is down instead of being queued, and after a failed connection attempt the next one waits 5 s; meanwhile, and
 * while another thread is connecting, calls fail immediately. A Redis outage therefore surfaces as
 * {@link BudgetStoreUnavailableException} on reads (the guard decides whether that blocks) and as a logged,
 * counted failure on writes, never as a slow request.
 */
@Component
@ConditionalOnProperty(name = "aigate.budget.store", havingValue = "redis")
public class RedisBudgetLedger implements BudgetLedger {

    private static final Logger log = LoggerFactory.getLogger(RedisBudgetLedger.class);

    private static final String CHARGE = """
            redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
            redis.call('PEXPIRE', KEYS[1], ARGV[3])
            return 1
            """;

    private static final String USAGE = """
            redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[1])
            return redis.call('ZRANGEBYSCORE', KEYS[1], ARGV[1], '+inf')
            """;

    private final RedisClient client;
    private final String prefix;
    private final MeterRegistry metrics;
    private static final Duration TIMEOUT = Duration.ofMillis(300);
    private static final long RECONNECT_BACKOFF_NANOS = Duration.ofSeconds(5).toNanos();

    private final ReentrantLock connecting = new ReentrantLock();
    private volatile StatefulRedisConnection<String, String> connection;
    private volatile long nextConnectAttempt;

    public RedisBudgetLedger(@Value("${aigate.budget.redis-url}") String url,
                             @Value("${aigate.budget.redis-key-prefix:aigate:budget:}") String prefix,
                             MeterRegistry metrics) {
        var uri = RedisURI.create(url);
        uri.setTimeout(TIMEOUT);
        this.client = RedisClient.create(uri);
        client.setOptions(ClientOptions.builder()
                .socketOptions(SocketOptions.builder().connectTimeout(TIMEOUT).build())
                .disconnectedBehavior(ClientOptions.DisconnectedBehavior.REJECT_COMMANDS)
                .build());
        this.prefix = prefix;
        this.metrics = metrics;
        log.info("Budgets shared through Redis at {}:{}", uri.getHost(), uri.getPort());
    }

    @Override
    public void charge(String clientId, Charge charge, Duration window) {
        var member = charge.at().toEpochMilli() + ":" + UUID.randomUUID().toString().substring(0, 8) + ":"
                + charge.tokens() + ":" + String.format(Locale.ROOT, "%.9f", charge.costUsd()) + ":"
                + charge.modelMillis();
        try {
            connection().sync().eval(CHARGE, ScriptOutputType.INTEGER, new String[] {prefix + clientId},
                    String.valueOf(charge.at().toEpochMilli()), member,
                    String.valueOf(window.plusMinutes(1).toMillis()));
        } catch (RuntimeException e) {
            metrics.counter("aigate.budget.store.errors", "operation", "charge").increment();
            log.warn("Could not record budget charge for {} in Redis: {}", clientId, e.getMessage());
        }
    }

    @Override
    public Usage usage(String clientId, Duration window) {
        List<String> members;
        try {
            var since = Instant.now().minus(window).toEpochMilli();
            members = connection().sync().eval(USAGE, ScriptOutputType.MULTI, new String[] {prefix + clientId},
                    String.valueOf(since));
        } catch (RuntimeException e) {
            metrics.counter("aigate.budget.store.errors", "operation", "usage").increment();
            throw new BudgetStoreUnavailableException("budget store unavailable: " + e.getMessage(), e);
        }
        long tokens = 0;
        double cost = 0;
        long millis = 0;
        for (var member : members) {
            var parts = member.split(":");
            tokens += Long.parseLong(parts[2]);
            cost += Double.parseDouble(parts[3]);
            millis += Long.parseLong(parts[4]);
        }
        return new Usage(tokens, cost, millis / 1000.0, members.size());
    }

    /** Connected on first use, so the gateway starts even while Redis is still coming up. */
    private StatefulRedisConnection<String, String> connection() {
        var current = connection;
        if (current != null && current.isOpen()) {
            return current;
        }
        if (System.nanoTime() < nextConnectAttempt || !connecting.tryLock()) {
            throw new RedisException("Redis unavailable, not retrying yet");
        }
        try {
            if (connection == null || !connection.isOpen()) {
                try {
                    connection = client.connect();
                } catch (RuntimeException e) {
                    nextConnectAttempt = System.nanoTime() + RECONNECT_BACKOFF_NANOS;
                    throw e;
                }
            }
            return connection;
        } finally {
            connecting.unlock();
        }
    }

    @PreDestroy
    void close() {
        if (connection != null) {
            connection.close();
        }
        client.shutdown();
    }
}
