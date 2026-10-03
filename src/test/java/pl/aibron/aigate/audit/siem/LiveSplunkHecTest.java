package pl.aibron.aigate.audit.siem;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The HEC sink against a real Splunk Enterprise 10.6. The image is amd64-only and takes minutes to start (longer
 * under emulation on ARM), so this runs only with AIGATE_LIVE=true and Docker:
 *
 *     AIGATE_LIVE=true ./mvnw test -Dtest=LiveSplunkHecTest
 */
@DirtiesContext
@EnabledIfEnvironmentVariable(named = "AIGATE_LIVE", matches = "true")
@EnabledIf("pl.aibron.aigate.DockerAvailable#dockerAvailable")
@DisplayName("Live: Splunk HEC sink against Splunk Enterprise 10.6 (AIGATE_LIVE=true)")
class LiveSplunkHecTest extends GatewayTestSupport {

    private static final String TOKEN = "3f6e1c0a-7b2d-4e5f-9a81-0c2d4b6e8f10";
    private static final String PASSWORD = "Live-test-1234";
    private static GenericContainer<?> splunk;

    @DynamicPropertySource
    static void hecToken(DynamicPropertyRegistry registry) {
        registry.add("AIGATE_LIVE_HEC_TOKEN", () -> TOKEN);
    }

    @BeforeAll
    static void startSplunk() throws Exception {
        splunk = new GenericContainer<>("splunk/splunk:10.6.0")
                .withCreateContainerCmdModifier(cmd -> cmd.withPlatform("linux/amd64"))
                .withEnv("SPLUNK_START_ARGS", "--accept-license")
                .withEnv("SPLUNK_GENERAL_TERMS", "--accept-sgt-current-at-splunk-com")
                .withEnv("SPLUNK_PASSWORD", PASSWORD)
                .withCopyToContainer(Transferable.of("""
                        [http]
                        disabled = 0
                        enableSSL = 0

                        [http://aigate_live]
                        disabled = 0
                        token = %s
                        index = aigate_live
                        indexes = aigate_live
                        """.formatted(TOKEN)), "/opt/splunk/etc/apps/aigate_live/default/inputs.conf")
                .withCopyToContainer(Transferable.of("""
                        [aigate_live]
                        homePath = $SPLUNK_DB/aigate_live/db
                        coldPath = $SPLUNK_DB/aigate_live/colddb
                        thawedPath = $SPLUNK_DB/aigate_live/thaweddb
                        """), "/opt/splunk/etc/apps/aigate_live/default/indexes.conf")
                .withExposedPorts(8088, 8089)
                .waitingFor(Wait.forHttp("/services/collector/health").forPort(8088).forStatusCode(200)
                        .withStartupTimeout(Duration.ofMinutes(10)));
        splunk.start();

        var policy = Files.readString(POLICY_DIR.resolve("policy.yaml"));
        Files.writeString(POLICY_DIR.resolve("policy.yaml"), policy + """

                audit:
                  sinks:
                    - type: splunk_hec
                      name: splunk-live
                      url: http://%s:%d/services/collector/event
                      token_env: AIGATE_LIVE_HEC_TOKEN
                      index: aigate_live
                      batch_interval: 500ms
                """.formatted(splunk.getHost(), splunk.getMappedPort(8088)));
    }

    @AfterAll
    static void stopSplunk() throws Exception {
        if (splunk != null) {
            splunk.stop();
        }
        Files.copy(Path.of("src/test/resources/policy/policy.yaml"), POLICY_DIR.resolve("policy.yaml"),
                StandardCopyOption.REPLACE_EXISTING);
    }

    @Test
    @DisplayName("indexed: decisions reach Splunk with millisecond time and masked text only")
    void indexed() throws Exception {
        Thread.sleep(3000);
        assertThat(chat(SANDBOX_KEY, "llama3.2:3b", "live splunk check").statusCode()).isEqualTo(200);
        assertThat(chat(FINANCE_APP_KEY, "llama3.2:3b", "live splunk client 44051401359").statusCode()).isEqualTo(403);

        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        String counts = "";
        while (System.nanoTime() < deadline) {
            counts = search("search index=aigate_live source=aigate \"live splunk\" | stats count");
            if (counts.contains("\n2") || counts.matches("(?s).*\\n\"?2\"?\\s*$")) {
                break;
            }
            Thread.sleep(3000);
        }
        assertThat(counts).as("events indexed in Splunk").containsPattern("\\n\"?2\"?");
        assertThat(search("search index=aigate_live 44051401359 | stats count")).containsPattern("\\n\"?0\"?");
        assertThat(search("search index=aigate_live \"live splunk check\" | eval ms=round((_time-floor(_time))*1000) | table ms"))
                .as("subsecond _time from the plain-decimal time field").doesNotContainPattern("\\n\"?0\"?\\s*$");
    }

    private static String search(String query) throws Exception {
        var result = splunk.execInContainer("curl", "-sk", "-u", "admin:" + PASSWORD,
                "https://localhost:8089/services/search/jobs/export", "-d", "search=" + query,
                "-d", "output_mode=csv");
        return result.getStdout().trim();
    }
}
