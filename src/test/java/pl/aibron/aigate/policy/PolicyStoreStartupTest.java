package pl.aibron.aigate.policy;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Policy: start with a broken file")
class PolicyStoreStartupTest {

    @TempDir
    Path dir;

    String valid;
    Path lastKnownGood;

    @BeforeEach
    void setUp() throws Exception {
        valid = Files.readString(Path.of("policy/policy.yaml"));
        lastKnownGood = dir.resolve("data/policy.last-known-good.yaml");
    }

    @Test
    @DisplayName("saved: a valid policy is copied as the last known good")
    void savesLastKnownGood() throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), valid);

        var store = new PolicyStore(dir, lastKnownGood);

        assertThat(store.active().fromLastKnownGood()).isFalse();
        assertThat(Files.readString(lastKnownGood)).isEqualTo(valid);
    }

    @Test
    @DisplayName("recovered: broken file at startup runs the last known good policy and reports the errors")
    void startsFromLastKnownGood() throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), valid);
        new PolicyStore(dir, lastKnownGood);
        Files.writeString(dir.resolve("policy.yaml"), valid.replace("on_secret: block", "on_secrets: block"));

        var store = new PolicyStore(dir, lastKnownGood);

        assertThat(store.active().fromLastKnownGood()).isTrue();
        assertThat(store.current().client("demo-agent")).isPresent();
        assertThat(store.lastReload().applied()).isFalse();
        assertThat(store.lastReload().errors()).anyMatch(e -> e.contains("last known good"))
                .anyMatch(e -> e.contains("on_secrets"));
    }

    @Test
    @DisplayName("recovered: fixing the file afterwards applies it and refreshes the last known good")
    void fixAfterRecovery() throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), valid);
        new PolicyStore(dir, lastKnownGood);
        Files.writeString(dir.resolve("policy.yaml"), "version: 1\nnot: [valid");
        var store = new PolicyStore(dir, lastKnownGood);

        var fixed = valid.replace("max_tokens: 50000", "max_tokens: 40000");
        Files.writeString(dir.resolve("policy.yaml"), fixed);
        var outcome = store.reload();

        assertThat(outcome.applied()).isTrue();
        assertThat(store.active().fromLastKnownGood()).isFalse();
        assertThat(Files.readString(lastKnownGood)).isEqualTo(fixed);
    }

    @Test
    @DisplayName("rejected: a broken edit never overwrites the last known good")
    void brokenEditKeepsFallback() throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), valid);
        var store = new PolicyStore(dir, lastKnownGood);
        Files.writeString(dir.resolve("policy.yaml"), "garbage: [");

        store.reload();

        assertThat(Files.readString(lastKnownGood)).isEqualTo(valid);
    }

    @Test
    @DisplayName("refused: first start with a broken file and no fallback fails fast")
    void noFallbackFailsFast() throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), "garbage: [");

        assertThatThrownBy(() -> new PolicyStore(dir, lastKnownGood)).isInstanceOf(InvalidPolicyException.class);
    }

    @Test
    @DisplayName("recovered: policy file deleted at startup also falls back")
    void missingFile() throws Exception {
        Files.writeString(dir.resolve("policy.yaml"), valid);
        new PolicyStore(dir, lastKnownGood);
        Files.delete(dir.resolve("policy.yaml"));

        assertThat(new PolicyStore(dir, lastKnownGood).active().fromLastKnownGood()).isTrue();
    }
}
