package pl.aibron.aigate.signatures;

import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.audit.AuditEvent;
import pl.aibron.aigate.audit.AuditRoute;

/**
 * Checks every few seconds whether the policy's refresh interval has passed, so a change of the interval in the
 * policy takes effect without a restart.
 */
@Component
public class SignatureFeedRoute extends RouteBuilder {

    private final SignatureFeed feed;
    private final AuditRoute audit;

    public SignatureFeedRoute(SignatureFeed feed, AuditRoute audit) {
        this.feed = feed;
        this.audit = audit;
    }

    @Override
    public void configure() {
        from("timer:signature-feed?delay=1000&period=5000").routeId("signature-feed")
                .filter(exchange -> feed.due())
                .process(exchange -> {
                    if (feed.refresh()) {
                        var status = feed.status();
                        audit.publish(AuditEvent.feedUpdate(status.version(), status.count(), status.origin()));
                    }
                });
    }
}
