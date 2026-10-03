package pl.aibron.aigate.gateway;

import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class GuardWarmupRoute extends RouteBuilder {

    private final SemanticGuard guard;

    public GuardWarmupRoute(SemanticGuard guard) {
        this.guard = guard;
    }

    @Override
    public void configure() {
        from("timer:guard-warmup?delay=500&period={{aigate.guards.keep-warm-ms}}")
                .routeId("guard-warmup")
                .autoStartup("{{aigate.guards.warmup-enabled}}")
                .process(exchange -> guard.warmUp());
    }
}
