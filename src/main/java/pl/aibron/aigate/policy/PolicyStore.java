package pl.aibron.aigate.policy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Holds the active policy. Requests read it once at the start and keep that snapshot, so a reload never changes
 * the rules halfway through a request.
 */
@Component
public class PolicyStore {

    public static final String FILE_NAME = "policy.yaml";

    private static final Logger log = LoggerFactory.getLogger(PolicyStore.class);

    public record Active(Policy policy, Instant loadedAt, int revision) { }

    public record ReloadOutcome(boolean applied, Instant at, List<String> errors) { }

    private final Path file;
    private final AtomicReference<Active> active = new AtomicReference<>();
    private final AtomicReference<ReloadOutcome> lastReload = new AtomicReference<>();

    public PolicyStore(@Value("${aigate.policy.dir}") Path dir) throws InvalidPolicyException {
        this.file = dir.resolve(FILE_NAME);
        // An invalid policy at startup is fatal: there is no previous version to fall back to.
        active.set(new Active(PolicyLoader.load(file), Instant.now(), 1));
        lastReload.set(new ReloadOutcome(true, Instant.now(), List.of()));
        log.info("Policy loaded from {}", file.toAbsolutePath());
    }

    public Policy current() {
        return active.get().policy();
    }

    public Active active() {
        return active.get();
    }

    public ReloadOutcome lastReload() {
        return lastReload.get();
    }

    public Path file() {
        return file;
    }

    public ReloadOutcome reload() {
        ReloadOutcome outcome;
        try {
            var policy = PolicyLoader.load(file);
            var previous = active.get();
            active.set(new Active(policy, Instant.now(), previous.revision() + 1));
            outcome = new ReloadOutcome(true, Instant.now(), List.of());
            log.info("Policy reloaded, revision {}", previous.revision() + 1);
        } catch (InvalidPolicyException e) {
            outcome = new ReloadOutcome(false, Instant.now(), e.errors());
            log.warn("Policy reload rejected, keeping revision {}: {}", active.get().revision(), e.getMessage());
        }
        lastReload.set(outcome);
        return outcome;
    }
}
