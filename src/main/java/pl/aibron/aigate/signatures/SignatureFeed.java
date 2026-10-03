package pl.aibron.aigate.signatures;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.policy.PolicyStore;

/**
 * Holds the active attack signatures. Starts from the copy bundled in the jar, then follows the feed URL from the
 * policy. A failed or invalid fetch keeps the current set, so an outage of the feed never removes protection.
 */
@Component
public class SignatureFeed {

    public record Status(String version, String source, String origin, Instant loadedAt, int count,
                         Instant lastAttempt, String lastError) { }

    private static final Logger log = LoggerFactory.getLogger(SignatureFeed.class);
    private static final Duration FETCH_TIMEOUT = Duration.ofSeconds(5);

    private final PolicyStore policyStore;
    private final String urlOverride;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(FETCH_TIMEOUT).build();
    private final AtomicReference<SignatureSet> active = new AtomicReference<>();
    private volatile Instant lastAttempt;
    private volatile String lastError;

    public SignatureFeed(PolicyStore policyStore, @Value("${aigate.signatures.feed-url:}") String urlOverride)
            throws IOException {
        this.policyStore = policyStore;
        this.urlOverride = urlOverride;
        try (var in = SignatureFeed.class.getResourceAsStream("/signatures/bundled.json")) {
            if (in == null) {
                throw new IllegalStateException("signatures/bundled.json missing from the classpath");
            }
            active.set(SignatureSet.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8), "bundled"));
        }
    }

    public SignatureSet current() {
        return active.get();
    }

    public Status status() {
        var set = active.get();
        return new Status(set.version(), set.source(), set.origin(), set.loadedAt(), set.signatures().size(),
                lastAttempt, lastError);
    }

    /** The URL from the policy, unless an environment override is set (e.g. a container hostname). */
    public String feedUrl() {
        if (urlOverride != null && !urlOverride.isBlank()) {
            return urlOverride;
        }
        var signatures = policyStore.current().signatures();
        return signatures == null ? null : signatures.feedUrl();
    }

    public boolean due() {
        var signatures = policyStore.current().signatures();
        if (feedUrl() == null || signatures == null) {
            return false;
        }
        var refresh = signatures.refresh() == null ? Duration.ofMinutes(15) : signatures.refreshDuration();
        return lastAttempt == null || Instant.now().isAfter(lastAttempt.plus(refresh));
    }

    /** Returns true when a new version was applied. */
    public synchronized boolean refresh() {
        var url = feedUrl();
        lastAttempt = Instant.now();
        if (url == null) {
            return false;
        }
        try {
            var response = http.send(HttpRequest.newBuilder(URI.create(url)).timeout(FETCH_TIMEOUT).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode());
            }
            var fetched = SignatureSet.parse(response.body(), url);
            lastError = null;
            var previous = active.get();
            if (fetched.version() != null && fetched.version().equals(previous.version())
                    && fetched.signatures().size() == previous.signatures().size() && !"bundled".equals(previous.origin())) {
                return false;
            }
            active.set(fetched);
            log.info("Signature feed {} applied: {} signatures from {}", fetched.version(), fetched.signatures().size(), url);
            return true;
        } catch (IOException | IllegalArgumentException e) {
            lastError = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            log.warn("Signature feed fetch from {} failed, keeping version {}: {}", url, active.get().version(), lastError);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
