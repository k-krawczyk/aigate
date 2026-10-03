package pl.aibron.aigate.corpus;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import pl.aibron.aigate.GatewayTestSupport;
import pl.aibron.aigate.gateway.StubUpstream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Runs every case of testdata/test-cases.json through the full gateway and compares the audited decision with
 * the expected one. The corpus was written separately from the code, as a red-team list.
 *
 * <p>Skipped here: budget cases (they need policy edits; see BudgetGovernanceTest) and the semantic group, whose
 * verdicts come from real guard models (see the live evaluation in the README).
 */
@DisplayName("Threat corpus (testdata/test-cases.json)")
class ThreatCorpusTest extends GatewayTestSupport {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> NEEDS_LIVE_MODELS = Set.of("semantic", "budget");

    @Autowired
    JdbcTemplate jdbc;

    static Stream<Arguments> cases() throws Exception {
        var corpus = JSON.readTree(Files.readString(Path.of("testdata/test-cases.json")));
        var list = new ArrayList<Arguments>();
        for (JsonNode c : corpus.path("cases")) {
            if (NEEDS_LIVE_MODELS.contains(c.path("group").asText())) {
                continue;
            }
            var name = c.path("id").asText() + " " + c.path("expected").asText() + ": " + c.path("description").asText();
            list.add(Arguments.of(Named.of(name, c)));
        }
        return list.stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void decision(JsonNode testCase) throws Exception {
        var expected = testCase.path("expected").asText();
        var response = send(testCase);

        var id = response.headers().firstValue("X-AIGate-Request-Id")
                .orElseGet(() -> response.body().replaceAll("(?s).*\"audit_id\":\"([^\"]+)\".*", "$1"));
        assertThat(auditedDecision(id)).as("decision for %s, body %s", testCase.path("id").asText(), response.body())
                .isEqualTo(expected);
    }

    private java.net.http.HttpResponse<String> send(JsonNode c) throws Exception {
        var group = c.path("group").asText();
        var id = c.path("id").asText();
        var text = c.path("text").asText("");
        if (group.equals("access")) {
            return switch (id) {
                case "access-01" -> chat(null, "llama3.2:3b", text);
                case "access-02" -> chat("not-a-real-key", "llama3.2:3b", text);
                default -> chat(DEMO_AGENT_KEY, "gpt-4o", text);
            };
        }
        if (c.has("tool_call")) {
            var call = c.path("tool_call");
            return chat(DEMO_AGENT_KEY, "llama3.2:3b",
                    "@tool " + call.path("name").asText() + " " + call.path("arguments").toString());
        }
        if (c.has("tools_offered")) {
            var tools = JSON.createArrayNode();
            for (JsonNode name : c.path("tools_offered")) {
                tools.addObject().put("type", "function").putObject("function").put("name", name.asText())
                        .putObject("parameters").put("type", "object");
            }
            var body = JSON.createObjectNode().put("model", "llama3.2:3b");
            body.set("tools", tools);
            body.putArray("messages").addObject().put("role", "user").put("content", text);
            return post(DEMO_AGENT_KEY, body.toString());
        }
        if (c.path("direction").asText().equals("response")) {
            StubUpstream.FIXTURES.put(id, text);
            return chat(DEMO_AGENT_KEY, "llama3.2:3b", "@fixture " + id);
        }
        return chat(DEMO_AGENT_KEY, "llama3.2:3b", text);
    }

    private String auditedDecision(String id) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            List<String> rows = jdbc.queryForList("SELECT decision FROM audit_event WHERE id = ?", String.class, id);
            if (!rows.isEmpty()) {
                return rows.getFirst();
            }
            Thread.sleep(25);
        }
        throw new AssertionError("no audit event " + id);
    }
}
