package pl.aibron.aigate.dashboard;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * A chat box for trying the gateway by hand. It calls the public /v1/chat/completions endpoint over HTTP with the
 * chosen API key, exactly like any client would, then shows what the gateway decided and why.
 */
@Controller
public class PlaygroundController {

    public record Result(int status, String answer, String error, Map<String, Object> audit,
                         Map<String, Long> steps, long roundTripMs) { }

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private final AuditQueries audit;
    private final Environment environment;

    public PlaygroundController(AuditQueries audit, Environment environment) {
        this.audit = audit;
        this.environment = environment;
    }

    @GetMapping("/dashboard/playground")
    public String page(Model model) {
        model.addAttribute("view", "playground");
        return "playground";
    }

    @PostMapping("/dashboard/playground/send")
    public String send(@RequestParam String apiKey, @RequestParam String model, @RequestParam String prompt,
                       @RequestParam(required = false) String system, Model view) throws Exception {
        var body = JSON.createObjectNode().put("model", model).put("max_tokens", 300);
        var messages = body.putArray("messages");
        if (system != null && !system.isBlank()) {
            messages.addObject().put("role", "system").put("content", system);
        }
        messages.addObject().put("role", "user").put("content", prompt);

        var port = environment.getProperty("local.server.port", "8080");
        long start = System.nanoTime();
        var response = HTTP.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/v1/chat/completions"))
                        .timeout(Duration.ofMinutes(3))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + apiKey)
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(),
                HttpResponse.BodyHandlers.ofString());
        long roundTrip = (System.nanoTime() - start) / 1_000_000;

        var json = JSON.readTree(response.body());
        var answer = json.path("choices").path(0).path("message").path("content").asText(null);
        var toolCalls = json.path("choices").path(0).path("message").path("tool_calls");
        if ((answer == null || answer.isBlank()) && toolCalls.size() > 0) {
            answer = "Tool call: " + toolCalls.toString();
        }
        var error = json.path("error").path("message").asText(null);
        var id = response.headers().firstValue("X-AIGate-Request-Id").orElse(json.path("error").path("audit_id").asText(null));

        Map<String, Object> row = null;
        for (int i = 0; i < 40 && id != null && row == null; i++) {
            row = audit.byId(id);
            if (row == null) {
                Thread.sleep(25);
            }
        }
        Map<String, Long> steps = new LinkedHashMap<>();
        if (row != null && row.get("STEP_MICROS") != null) {
            steps = JSON.readValue((String) row.get("STEP_MICROS"), new TypeReference<>() { });
        }
        view.addAttribute("result", new Result(response.statusCode(), answer, error, row, steps, roundTrip));
        return "playground :: result";
    }
}
