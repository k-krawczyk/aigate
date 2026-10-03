package pl.aibron.aigate.policy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Holds the active policy. Requests read it once at the start and keep that snapshot, so a reload never changes
 * the rules halfway through a request.
 *
 * <p>Every policy that passes validation is also copied to a last-known-good file. If the policy file is broken
 * when the gateway starts (an operator broke it and then restarted), the gateway starts from that copy and reports
 * the errors, instead of refusing to start and taking every client down with it.
 */
@Component
public class PolicyStore {

    public static final String FILE_NAME = "policy.yaml";

    private static final Logger log = LoggerFactory.getLogger(PolicyStore.class);

    public record Active(Policy policy, Instant loadedAt, int revision, boolean fromLastKnownGood) { }

    public record ReloadOutcome(boolean applied, Instant at, List<String> errors) { }

    private final Path file;
    private final Path lastKnownGood;
    private final AtomicReference<Active> active = new AtomicReference<>();
    private final AtomicReference<ReloadOutcome> lastReload = new AtomicReference<>();

    public PolicyStore(@Value("${aigate.policy.dir}") Path dir,
                       @Value("${aigate.policy.last-known-good}") Path lastKnownGood) throws InvalidPolicyException {
        this.file = dir.resolve(FILE_NAME);
        this.lastKnownGood = lastKnownGood;
        try {
            var text = read(file);
            active.set(new Active(PolicyLoader.parse(text), Instant.now(), 1, false));
            lastReload.set(new ReloadOutcome(true, Instant.now(), List.of()));
            saveLastKnownGood(text);
            log.info("Policy loaded from {}", file.toAbsolutePath());
        } catch (InvalidPolicyException e) {
            if (!Files.isReadable(lastKnownGood)) {
                // First start with a broken file: there is nothing safe to fall back to.
                throw e;
            }
            active.set(new Active(PolicyLoader.parse(read(lastKnownGood)), Instant.now(), 1, true));
            var errors = new ArrayList<String>();
            errors.add("policy.yaml was invalid at startup; running the last known good policy until it is fixed");
            errors.addAll(e.errors());
            lastReload.set(new ReloadOutcome(false, Instant.now(), List.copyOf(errors)));
            log.error("Policy file {} is invalid, started from last known good copy {}: {}",
                    file.toAbsolutePath(), lastKnownGood.toAbsolutePath(), e.getMessage());
        }
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
            var text = read(file);
            var policy = PolicyLoader.parse(text);
            var previous = active.get();
            active.set(new Active(policy, Instant.now(), previous.revision() + 1, false));
            outcome = new ReloadOutcome(true, Instant.now(), List.of());
            saveLastKnownGood(text);
            log.info("Policy reloaded, revision {}", previous.revision() + 1);
        } catch (InvalidPolicyException e) {
            outcome = new ReloadOutcome(false, Instant.now(), e.errors());
            log.warn("Policy reload rejected, keeping revision {}: {}", active.get().revision(), e.getMessage());
        }
        lastReload.set(outcome);
        return outcome;
    }

    private static String read(Path path) throws InvalidPolicyException {
        try {
            return Files.readString(path);
        } catch (IOException e) {
            throw new InvalidPolicyException(List.of("cannot read " + path + ": " + e.getMessage()));
        }
    }

    /** Written atomically, so a crash mid-write cannot leave a half file as the fallback. */
    private void saveLastKnownGood(String text) {
        try {
            if (lastKnownGood.getParent() != null) {
                Files.createDirectories(lastKnownGood.getParent());
            }
            var temp = lastKnownGood.resolveSibling(lastKnownGood.getFileName() + ".tmp");
            Files.writeString(temp, text);
            Files.move(temp, lastKnownGood, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            // Losing the fallback copy must not stop the gateway from applying a valid policy.
            log.warn("Could not save last known good policy to {}: {}", lastKnownGood, e.getMessage());
        }
    }
}
