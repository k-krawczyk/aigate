package pl.aibron.aigate.policy;

import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

@DirtiesContext
@DisplayName("Policy: hot reload without restart")
class PolicyHotReloadTest extends GatewayTestSupport {

    private static final Duration RELOAD_TIMEOUT = Duration.ofSeconds(15);

    @Autowired
    PolicyStore store;

    @AfterEach
    void restorePolicy() throws Exception {
        write(Files.readString(java.nio.file.Path.of("src/test/resources/policy/policy.yaml")));
        awaitTrue(() -> store.lastReload().applied() && store.current().client("demo-agent").orElseThrow()
                .mayUse("llama3.2:3b"));
    }

    @Test
    @DisplayName("applied: revoking a model takes effect on the next request")
    void revokeModel() throws Exception {
        assertThat(chat(DEMO_AGENT_KEY, "llama3.2:3b", "hello").statusCode()).isEqualTo(200);
        int revision = store.active().revision();

        write(policy().replace("models: [llama3.2:3b]\n    tools:", "models: [granite4:3b]\n    tools:"));

        awaitTrue(() -> store.active().revision() > revision);
        assertThat(chat(DEMO_AGENT_KEY, "llama3.2:3b", "hello").statusCode()).isEqualTo(403);
    }

    @Test
    @DisplayName("applied: editor-style save (write temp file, rename over) is picked up")
    void atomicRenameSave() throws Exception {
        int revision = store.active().revision();
        var temp = POLICY_DIR.resolve(".policy.yaml.swp");
        Files.writeString(temp, policy() + "\n# saved by an editor\n");
        Files.move(temp, POLICY_DIR.resolve("policy.yaml"), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);

        awaitTrue(() -> store.active().revision() > revision);
    }

    @Test
    @DisplayName("applied: lowering a client's token budget to 0 refuses its next request")
    void budgetChange() throws Exception {
        assertThat(chat(SANDBOX_KEY, "llama3.2:3b", "budget probe one").statusCode()).isEqualTo(200);
        int revision = store.active().revision();

        write(policy().replace("profile: permissive\n    models: [llama3.2:3b, granite4:3b]",
                "profile: permissive\n    models: [llama3.2:3b, granite4:3b]\n    budgets:\n      max_tokens: 0"));

        awaitTrue(() -> store.active().revision() > revision);
        assertThat(chat(SANDBOX_KEY, "llama3.2:3b", "budget probe two").statusCode()).isEqualTo(429);
    }

    @Test
    @DisplayName("rejected: broken policy keeps the previous one active and records the errors")
    void invalidEditKeepsPrevious() throws Exception {
        int revision = store.active().revision();

        write(policy().replace("profile: balanced", "profile: does-not-exist"));

        awaitTrue(() -> !store.lastReload().applied());
        assertThat(store.active().revision()).isEqualTo(revision);
        assertThat(store.lastReload().errors()).anyMatch(e -> e.contains("does-not-exist"));
        assertThat(chat(DEMO_AGENT_KEY, "llama3.2:3b", "hello").statusCode()).isEqualTo(200);
    }

    private static String policy() throws Exception {
        return Files.readString(POLICY_DIR.resolve("policy.yaml"));
    }

    private static void write(String content) throws Exception {
        Files.writeString(POLICY_DIR.resolve("policy.yaml"), content);
    }

    private static void awaitTrue(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + RELOAD_TIMEOUT.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition not met within " + RELOAD_TIMEOUT);
            }
            Thread.sleep(100);
        }
    }
}
