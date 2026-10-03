package pl.aibron.aigate.gateway;

import static pl.aibron.aigate.gateway.GatewayPipeline.timed;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class ChatCompletionsRoute extends RouteBuilder {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final GatewayPipeline pipeline;

    public ChatCompletionsRoute(GatewayPipeline pipeline) {
        this.pipeline = pipeline;
    }

    @Override
    public void configure() {
        onException(GatewayRejection.class)
                .handled(true)
                .process(ChatCompletionsRoute::writeRejection);

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
                .process(GatewayPipeline.startStep("upstream"))
                .to("direct:upstream")
                .process(GatewayPipeline.endStep("upstream"))
                .setHeader("X-AIGate-Request-Id", exchangeProperty(ExchangeKeys.REQUEST_ID));

        from("direct:upstream").routeId("upstream")
                // Inbound HTTP headers (Authorization, Host, CamelHttp*) must never leak to the model server.
                .removeHeaders("*")
                .setHeader(Exchange.HTTP_METHOD, constant("POST"))
                .setHeader(Exchange.CONTENT_TYPE, constant("application/json"))
                .to("{{aigate.upstream.uri}}")
                .convertBodyTo(String.class)
                .removeHeaders("*", Exchange.HTTP_RESPONSE_CODE)
                .setHeader(Exchange.CONTENT_TYPE, constant("application/json"));
    }

    private static void writeRejection(Exchange exchange) throws Exception {
        var rejection = exchange.getProperty(Exchange.EXCEPTION_CAUGHT, GatewayRejection.class);
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
