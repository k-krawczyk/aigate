package pl.aibron.aigate.audit.siem;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.audit.AuditEvent;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SIEM: Elastic Common Schema format")
class EcsFormatterTest {

    @Test
    @DisplayName("blocked request maps to ECS fields, the flat AIGate fields stay under aigate.*")
    void mapsToEcs() throws Exception {
        var event = new AuditEvent("e1", Instant.parse("2026-10-03T12:00:00Z"), AuditEvent.CHAT, "demo-agent",
                "f3a1", "anna.kowalska", "oidc:corporate", "llama3.2:3b", "request", "BLOCK", "sensitive_data",
                "LLM02", "pii.pesel", "Customer [PESEL] asks", 403, null, null, null, 4.25, Map.of(), 7,
                "blocked", "strict", List.of("ai-finance"));

        var json = new ObjectMapper().readTree(new ObjectMapper().writeValueAsString(
                EcsFormatter.ecs(event, Map.of("decision", "BLOCK", "profile", "strict"))));

        assertThat(json.path("@timestamp").asText()).isEqualTo("2026-10-03T12:00:00Z");
        assertThat(json.at("/event/action").asText()).isEqualTo("chat");
        assertThat(json.at("/event/outcome").asText()).isEqualTo("failure");
        assertThat(json.at("/event/duration").asLong()).isEqualTo(4_250_000L);
        assertThat(json.at("/user/name").asText()).isEqualTo("anna.kowalska");
        assertThat(json.at("/rule/name").asText()).isEqualTo("pii.pesel");
        assertThat(json.at("/rule/category").asText()).isEqualTo("LLM02");
        assertThat(json.at("/http/response/status_code").asInt()).isEqualTo(403);
        assertThat(json.path("message").asText()).isEqualTo("Customer [PESEL] asks");
        assertThat(json.at("/aigate/profile").asText()).isEqualTo("strict");
    }

    @Test
    @DisplayName("outcome: allowed and redacted are success, rejected policy edits are failure")
    void outcomes() {
        assertThat(EcsFormatter.outcome("ALLOW")).isEqualTo("success");
        assertThat(EcsFormatter.outcome("REDACT")).isEqualTo("success");
        assertThat(EcsFormatter.outcome("REJECTED")).isEqualTo("failure");
        assertThat(EcsFormatter.outcome(null)).isEqualTo("unknown");
    }
}
