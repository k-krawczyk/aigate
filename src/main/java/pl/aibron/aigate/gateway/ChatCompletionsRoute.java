package pl.aibron.aigate.gateway;

import static pl.aibron.aigate.gateway.GatewayPipeline.timed;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.budget.BudgetGuard;

@Component
public class ChatCompletionsRoute extends RouteBuilder {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final GatewayPipeline pipeline;
    private final ContentInspection contentInspection;
    private final ResponseInspection responseInspection;
    private final BudgetGuard budgetGuard;
    private final SemanticCheck semanticCheck;
    private final OutputSemanticCheck outputSemanticCheck;
    private final ToolDataInspection toolDataInspection;

    public ChatCompletionsRoute(GatewayPipeline pipeline, ContentInspection contentInspection,
                                ResponseInspection responseInspection, BudgetGuard budgetGuard,
                                SemanticCheck semanticCheck, OutputSemanticCheck outputSemanticCheck,
                                ToolDataInspection toolDataInspection) {
        this.toolDataInspection = toolDataInspection;
        this.semanticCheck = semanticCheck;
        this.outputSemanticCheck = outputSemanticCheck;
        this.pipeline = pipeline;
        this.contentInspection = contentInspection;
        this.responseInspection = responseInspection;
        this.budgetGuard = budgetGuard;
    }

    @Override
    public void configure() {
        onException(GatewayRejection.class)
                .handled(true)
                .process(ChatCompletionsRoute::writeRejection)
                .wireTap("direct:audit");

        // Anything unexpected still gets an OpenAI-style error and an audit event, never a stack trace.
        onException(Exception.class)
                .handled(true)
                .process(exchange -> {
                    var cause = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, Exception.class);
                    log.error("Unexpected gateway error", cause);
                    exchange.setProperty(Exchange.EXCEPTION_CAUGHT,
                            new GatewayRejection(500, "internal_error", "gateway_error", "Internal gateway error"));
                })
                .process(ChatCompletionsRoute::writeRejection)
                .wireTap("direct:audit");

        rest("/v1")
                .post("/chat/completions")
                .consumes("application/json")
                .produces("application/json")
                .to("direct:chat");

        from("direct:chat").routeId("chat")
                .convertBodyTo(String.class)
                .process(timed("parse", pipeline::begin))
                .process(timed("authenticate", pipeline::authenticate))
                .process(timed("model_allowlist", pipeline::authorizeModel))
                .process(timed("budget", budgetGuard::admit))
                .process(timed("request_rules", contentInspection::inspectRequest))
                .process(timed("tool_data", toolDataInspection::inspect))
                .process(timed("semantic", semanticCheck::evaluate))
                .process(GatewayPipeline.startStep("upstream"))
                .to("direct:upstream")
                .process(GatewayPipeline.endStep("upstream"))
                .process(budgetGuard::charge)
                .process(timed("response_rules", responseInspection::inspectResponse))
                .process(timed("output_semantic", outputSemanticCheck::evaluate))
                .setHeader("X-AIGate-Request-Id", exchangeProperty(ExchangeKeys.REQUEST_ID))
                .wireTap("direct:audit")
                .process(StreamAdapter::toEventStream);

        from("direct:upstream").routeId("upstream")
                // Inbound HTTP headers (Authorization, Host, CamelHttp*) must never leak to the model server.
                .removeHeaders("*")
                .setHeader(Exchange.HTTP_METHOD, constant("POST"))
                .setHeader(Exchange.CONTENT_TYPE, constant("application/json"))
                // Opens after half of the last 10 calls failed, so a dead model server costs clients
                // milliseconds instead of a connect timeout each, and is retried after 15 s.
                .circuitBreaker()
                    .resilience4jConfiguration()
                        .slidingWindowSize(10).minimumNumberOfCalls(5).failureRateThreshold(50)
                        .waitDurationInOpenState(15000).automaticTransitionFromOpenToHalfOpenEnabled(true)
                        .timeoutEnabled(true).timeoutDuration(120000)
                    .end()
                    .to("{{aigate.upstream.uri}}")
                .onFallback()
                    .process(exchange -> {
                        throw new GatewayRejection(503, "upstream_unavailable", "availability",
                                "Model server unavailable, try again later");
                    })
                .end()
                .convertBodyTo(String.class)
                .removeHeaders("*", Exchange.HTTP_RESPONSE_CODE)
                .setHeader(Exchange.CONTENT_TYPE, constant("application/json"));
    }

    private static void writeRejection(Exchange exchange) throws Exception {
        var rejection = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, GatewayRejection.class);
        exchange.setProperty(ExchangeKeys.DECISION, Decision.BLOCK);
        if (exchange.getProperty(ExchangeKeys.CATEGORY) == null) {
            exchange.setProperty(ExchangeKeys.CATEGORY, rejection.category());
            exchange.setProperty(ExchangeKeys.OWASP, rejection.owasp());
            exchange.setProperty(ExchangeKeys.DIRECTION, "request");
        }
        var error = JSON.createObjectNode();
        error.put("message", rejection.getMessage());
        error.put("type", rejection.openAiType());
        error.put("code", rejection.code());
        error.put("category", rejection.category());
        error.put("audit_id", exchange.getProperty(ExchangeKeys.REQUEST_ID, String.class));

        var message = exchange.getMessage();
        message.removeHeaders("*");
        message.setHeader(Exchange.HTTP_RESPONSE_CODE, rejection.status());
        message.setHeader(Exchange.CONTENT_TYPE, "application/json");
        message.setBody(JSON.writeValueAsString(JSON.createObjectNode().set("error", error)));
    }
}
