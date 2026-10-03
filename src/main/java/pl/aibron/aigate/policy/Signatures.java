package pl.aibron.aigate.policy;

import java.time.Duration;

public record Signatures(String feedUrl, String refresh) {

    public Duration refreshDuration() {
        return Durations.parse(refresh);
    }
}
