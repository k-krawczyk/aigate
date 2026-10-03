package pl.aibron.aigate.gateway;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Import(StubUpstream.class)
@DisplayName("Gateway pass-through")
class PassThroughTest {

    @Value("${local.server.port}")
    int port;

    @Test
    @DisplayName("benign chat completion reaches the model and the answer comes back unchanged")
    void forwardsBenignRequest() throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/chat/completions"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("""
                        {"model":"llama3.2:3b","messages":[{"role":"user","content":"What is the capital of Poland?"}]}
                        """))
                .build();

        var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(StubUpstream.MODEL_REPLY_PREFIX + "What is the capital of Poland?");
    }
}
