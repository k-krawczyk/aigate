package pl.aibron.aigate.audit.siem;

import io.micrometer.core.instrument.MeterRegistry;
import org.apache.camel.AggregationStrategy;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Batches Splunk HEC events with Camel's Aggregator: one HTTP request per batch_size events or per batch_interval,
 * whichever comes first, per sink. HEC accepts several event objects concatenated in one body, so a busy gateway
 * sends a few requests a second instead of one per decision.
 *
 * <p>The queue in front holds at most 10 000 events; when Splunk is down long enough to fill it, new events are
 * refused (and counted) instead of growing the heap.
 */
@Component
public class SplunkHecRoute extends RouteBuilder {

    static final String QUEUE = "seda:splunk-hec?size=10000&blockWhenFull=false";
    static final String SINK = "AigateSink";
    static final String URL = "AigateHecUrl";
    static final String TOKEN = "AigateHecToken";
    static final String BATCH_SIZE = "AigateBatchSize";
    static final String BATCH_MILLIS = "AigateBatchMillis";
    private static final String EVENTS = "AigateEvents";

    private static final Logger log = LoggerFactory.getLogger(SplunkHecRoute.class);

    private final MeterRegistry metrics;

    public SplunkHecRoute(MeterRegistry metrics) {
        this.metrics = metrics;
    }

    @Override
    public void configure() {
        from(QUEUE).routeId("splunk-hec-batch")
                .aggregate(header(SINK), new Concatenate())
                    .completionSize(header(BATCH_SIZE))
                    .completionTimeout(header(BATCH_MILLIS))
                    .completionTimeoutCheckerInterval(100)
                .to("direct:splunk-hec-send");

        from("direct:splunk-hec-send").routeId("splunk-hec-send")
                .onException(Exception.class)
                    .handled(true)
                    .process(exchange -> {
                        var cause = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
                        int events = exchange.getProperty(EVENTS, 1, Integer.class);
                        var sink = exchange.getProperty(SINK, String.class);
                        metrics.counter("aigate.audit.sink.failures", "sink", sink).increment(events);
                        log.warn("SIEM sink {} failed for a batch of {} events: {}", sink, events, cause.getMessage());
                    })
                .end()
                .process(exchange -> {
                    var message = exchange.getMessage();
                    exchange.setProperty(SINK, message.getHeader(SINK));
                    exchange.setProperty(URL, message.getHeader(URL));
                    var token = message.getHeader(TOKEN, String.class);
                    // Nothing from the audit exchange may leak into the HTTP request as a header.
                    message.removeHeaders("*");
                    message.setHeader(Exchange.HTTP_METHOD, "POST");
                    message.setHeader(Exchange.CONTENT_TYPE, "application/json");
                    message.setHeader("Authorization", "Splunk " + token);
                })
                .toD("${exchangeProperty." + URL + "}")
                .process(exchange -> metrics.counter("aigate.audit.sink.sent", "sink",
                        exchange.getProperty(SINK, String.class)).increment(exchange.getProperty(EVENTS, 1, Integer.class)));
    }

    /** Joins event objects with newlines, the HEC batch format, and counts them. */
    static final class Concatenate implements AggregationStrategy {

        @Override
        public Exchange aggregate(Exchange oldExchange, Exchange newExchange) {
            if (oldExchange == null) {
                newExchange.setProperty(EVENTS, 1);
                return newExchange;
            }
            var body = oldExchange.getMessage().getBody(String.class) + "\n" + newExchange.getMessage().getBody(String.class);
            oldExchange.getMessage().setBody(body);
            oldExchange.setProperty(EVENTS, oldExchange.getProperty(EVENTS, Integer.class) + 1);
            return oldExchange;
        }
    }
}
