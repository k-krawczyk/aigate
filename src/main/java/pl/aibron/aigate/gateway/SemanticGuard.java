package pl.aibron.aigate.gateway;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Asks two local models in parallel. Llama Guard 3 classifies harmful content (hazard categories S1-S14) but does
 * not flag prompt injection, so a second, general model judges injection with a dedicated prompt.
 *
 * <p>Granite Guardian 3 (2B, "jailbreak" risk) was tried first and dropped: on our calibration set it scored
 * ordinary requests such as "Check the status of order 1234" at 0.97. Granite 4 3B with the judge prompt kept
 * benign requests below 0.09 and attacks above 0.98, at about 70 ms.
 *
 * <p>Scores are probabilities from logprobs of the first answer token, so policy thresholds are real
 * probabilities, not string matches.
 */
@Component
public class SemanticGuard {

    public record Verdict(double harmScore, String harmCategory, double injectionScore, long millis) { }

    private static final ObjectMapper JSON = new ObjectMapper();
    /** What the small guard models are given at most; RiskScorer flags anything longer, see guardInput. */
    public static final int MAX_CHARS = 4000;

    private static final Map<String, String> HAZARDS = Map.ofEntries(
            Map.entry("S1", "violent crimes"), Map.entry("S2", "non-violent crimes"),
            Map.entry("S3", "sex-related crimes"), Map.entry("S4", "child sexual exploitation"),
            Map.entry("S5", "defamation"), Map.entry("S6", "specialized advice"), Map.entry("S7", "privacy"),
            Map.entry("S8", "intellectual property"), Map.entry("S9", "indiscriminate weapons"),
            Map.entry("S10", "hate"), Map.entry("S11", "suicide and self-harm"), Map.entry("S12", "sexual content"),
            Map.entry("S13", "elections"), Map.entry("S14", "code interpreter abuse"));

    private final ProducerTemplate producer;
    private final String uri;
    private final String harmModel;
    private final String injectionModel;
    private final Duration timeout;
    private final String judgePrompt;

    public SemanticGuard(ProducerTemplate producer,
                         @Value("${aigate.guards.uri}") String uri,
                         @Value("${aigate.guards.harm-model}") String harmModel,
                         @Value("${aigate.guards.injection-model}") String injectionModel,
                         @Value("${aigate.guards.timeout}") Duration timeout) {
        this.producer = producer;
        this.uri = uri;
        this.harmModel = harmModel;
        this.injectionModel = injectionModel;
        this.timeout = timeout;
        try (var in = SemanticGuard.class.getResourceAsStream("/prompts/injection-judge.txt")) {
            this.judgePrompt = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
        } catch (java.io.IOException | NullPointerException e) {
            throw new IllegalStateException("prompts/injection-judge.txt missing from the classpath", e);
        }
    }

    /** Loads both models into memory so the first real request does not pay the cold start (seconds). */
    public void warmUp() {
        call(guardRequest(harmModel, null, "hello"));
        call(guardRequest(injectionModel, judgePrompt, "hello"));
    }

    public Verdict evaluate(String text) throws Exception {
        long start = System.nanoTime();
        var input = guardInput(text);

        var harm = call(guardRequest(harmModel, null, input));
        var injection = call(guardRequest(injectionModel, judgePrompt, "USER TEXT:\n<<<\n" + input + "\n>>>"));
        CompletableFuture.allOf(harm, injection).get(timeout.toMillis(), TimeUnit.MILLISECONDS);

        var harmAnswer = JSON.readTree(harm.get());
        var injectionAnswer = JSON.readTree(injection.get());
        var harmText = content(harmAnswer);
        String category = null;
        var lines = harmText.split("\\s+");
        if (lines.length > 1) {
            category = lines[1] + " " + HAZARDS.getOrDefault(lines[1].replace(",", ""), "");
        }
        return new Verdict(
                probability(harmAnswer, "unsafe", "safe"),
                category == null ? null : category.trim(),
                probability(injectionAnswer, "yes", "no"),
                (System.nanoTime() - start) / 1_000_000);
    }

    /**
     * Head and tail of a long input. An attack usually sits at the start (instructions first, filler after) or at
     * the end (filler first), so both ends are kept rather than only the last part.
     */
    static String guardInput(String text) {
        if (text.length() <= MAX_CHARS) {
            return text;
        }
        int half = MAX_CHARS / 2;
        return text.substring(0, half) + "\n[...]\n" + text.substring(text.length() - half);
    }

    private CompletableFuture<String> call(String body) {
        return producer.asyncRequestBodyAndHeaders(uri, body,
                Map.of(Exchange.HTTP_METHOD, "POST", Exchange.CONTENT_TYPE, "application/json"), String.class);
    }

    private static String guardRequest(String model, String systemPrompt, String text) {
        var request = JSON.createObjectNode();
        request.put("model", model).put("temperature", 0).put("max_tokens", 8)
                .put("logprobs", true).put("top_logprobs", 5);
        var messages = request.putArray("messages");
        if (systemPrompt != null) {
            messages.addObject().put("role", "system").put("content", systemPrompt);
        }
        messages.addObject().put("role", "user").put("content", text);
        return request.toString();
    }

    private static String content(JsonNode answer) {
        return answer.path("choices").path(0).path("message").path("content").asText("").trim();
    }

    /**
     * P(positive) renormalised over the positive and negative first tokens. Falls back to the answer text when the
     * server returned no logprobs.
     */
    static double probability(JsonNode answer, String positive, String negative) {
        var first = answer.path("choices").path(0).path("logprobs").path("content").path(0);
        double pos = 0;
        double neg = 0;
        for (JsonNode candidate : first.path("top_logprobs")) {
            var token = candidate.path("token").asText("").trim().toLowerCase();
            double p = Math.exp(candidate.path("logprob").asDouble(Double.NEGATIVE_INFINITY));
            if (token.equals(positive)) {
                pos += p;
            } else if (token.equals(negative)) {
                neg += p;
            }
        }
        if (pos + neg > 0) {
            return pos / (pos + neg);
        }
        return content(answer).toLowerCase().startsWith(positive) ? 1.0 : 0.0;
    }

}
