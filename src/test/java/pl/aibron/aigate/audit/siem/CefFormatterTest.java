package pl.aibron.aigate.audit.siem;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.audit.AuditEvent;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SIEM: CEF over syslog formatting")
class CefFormatterTest {

    private static AuditEvent blocked(String excerpt) {
        return new AuditEvent("e1", Instant.parse("2026-10-03T12:00:00Z"), AuditEvent.CHAT, "finance-app", "finance-app",
                null, "api_key", "llama3.2:3b", "request", "BLOCK", "sensitive_data", "LLM02", "pii.pesel", excerpt,
                403, null, null, null, 4.2, Map.of("parse", 100L), 3, "Request blocked by policy: contains PESEL",
                "strict", List.of("ai-staff", "ai-finance"));
    }

    @Test
    @DisplayName("RFC 5424 header with local4 facility and warning severity for a block")
    void syslogHeader() {
        var line = CefFormatter.syslogLine(blocked("client [PESEL]"), "gw1");

        assertThat(line).startsWith("<164>1 2026-10-03T12:00:00Z gw1 aigate - chat - CEF:0|AIGate|AI Control Layer|0.1|sensitive_data|BLOCK sensitive_data|7|");
    }

    @Test
    @DisplayName("extensions carry client, decision, OWASP id, rules and the masked excerpt")
    void extensions() {
        var cef = CefFormatter.cef(blocked("client [PESEL]"));

        assertThat(cef).contains("act=BLOCK", "suser=finance-app", "cs1Label=owasp cs1=LLM02", "cs2=pii.pesel",
                "outcome=403", "msg=client [PESEL]", "externalId=e1", "cs5Label=profile cs5=strict",
                "cs6Label=groups cs6=ai-staff,ai-finance", "flexString1Label=authMethod flexString1=api_key",
                "cn3Label=policyRevision cn3=3");
    }

    @Test
    @DisplayName("escaping: '=' and newlines in values, '|' in header fields cannot break the record")
    void escaping() {
        var cef = CefFormatter.cef(blocked("a=b\nnext line \\ end"));

        assertThat(cef).contains("msg=a\\=b\\nnext line \\\\ end").doesNotContain("\n");
        assertThat(CefFormatter.header("x|y")).isEqualTo("x\\|y");
    }
}
