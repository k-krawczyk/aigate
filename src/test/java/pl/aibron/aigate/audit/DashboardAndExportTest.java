package pl.aibron.aigate.audit;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Reporting: dashboard and audit export")
class DashboardAndExportTest extends GatewayTestSupport {

    @Test
    @DisplayName("dashboard renders with decisions and masked excerpts")
    void dashboard() throws Exception {
        chat(FINANCE_APP_KEY, "llama3.2:3b", "client PESEL 44051401359");
        Thread.sleep(300);

        var page = get("/dashboard");

        assertThat(page.statusCode()).isEqualTo(200);
        assertThat(page.body()).contains("Recent events", "BLOCK", "[PESEL]").doesNotContain("44051401359");
    }

    @Test
    @DisplayName("export: JSONL and CSV contain events but no raw PII")
    void export() throws Exception {
        chat(DEMO_AGENT_KEY, "llama3.2:3b", "account PL61 1090 1014 0000 0712 1981 2874");
        Thread.sleep(300);

        var jsonl = get("/audit/export?format=jsonl");
        var csv = get("/audit/export?format=csv");

        assertThat(jsonl.body()).contains("\"decision\":\"REDACT\"").doesNotContain("1090 1014");
        assertThat(csv.body().lines().findFirst().orElseThrow()).startsWith("id,ts,event_type");
        assertThat(csv.body()).doesNotContain("1090 1014");
    }

    private HttpResponse<String> get(String path) throws Exception {
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
