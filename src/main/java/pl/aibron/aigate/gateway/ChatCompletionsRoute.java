package pl.aibron.aigate.gateway;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class ChatCompletionsRoute extends RouteBuilder {

    @Override
    public void configure() {
        rest("/v1")
                .post("/chat/completions")
                .consumes("application/json")
                .produces("application/json")
                .to("direct:chat");

        from("direct:chat").routeId("chat")
                .convertBodyTo(String.class)
                .to("direct:upstream");

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
}
