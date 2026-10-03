package pl.aibron.aigate.audit;

import java.util.concurrent.TimeUnit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

/**
 * Turns audit events into Micrometer metrics, so the same numbers reach /actuator/prometheus and any monitoring
 * stack without a second instrumentation path.
 */
@Component
public class MetricsSink implements AuditSink {

    private final MeterRegistry registry;

    public MetricsSink(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    public String name() {
        return "micrometer";
    }

    @Override
    public void publish(AuditEvent e) {
        if (!AuditEvent.CHAT.equals(e.eventType())) {
            Counter.builder("aigate.control.events").tag("type", e.eventType())
                    .tag("outcome", String.valueOf(e.decision())).register(registry).increment();
            return;
        }
        var client = e.clientId() == null ? "unknown" : e.clientId();
        Counter.builder("aigate.requests")
                .description("Governed chat completions by decision")
                .tag("client", client)
                .tag("decision", String.valueOf(e.decision()))
                .tag("category", e.category() == null ? "none" : e.category())
                .register(registry).increment();
        if (e.latencyMs() != null) {
            Timer.builder("aigate.request.latency").tag("decision", String.valueOf(e.decision()))
                    .publishPercentiles(0.5, 0.95, 0.99)
                    .register(registry).record((long) (e.latencyMs() * 1000), TimeUnit.MICROSECONDS);
        }
        if (e.stepMicros() != null) {
            e.stepMicros().forEach((step, micros) -> Timer.builder("aigate.step.latency")
                    .description("Time spent in one pipeline step")
                    .tag("step", step)
                    .publishPercentiles(0.5, 0.95, 0.99)
                    .register(registry).record(micros, TimeUnit.MICROSECONDS));
        }
        if (e.promptTokens() != null) {
            Counter.builder("aigate.tokens").tag("client", client).tag("model", String.valueOf(e.model()))
                    .register(registry).increment(e.promptTokens() + (e.completionTokens() == null ? 0 : e.completionTokens()));
        }
        if (e.costUsd() != null) {
            Counter.builder("aigate.cost.usd").tag("client", client).tag("model", String.valueOf(e.model()))
                    .register(registry).increment(e.costUsd());
        }
    }
}
