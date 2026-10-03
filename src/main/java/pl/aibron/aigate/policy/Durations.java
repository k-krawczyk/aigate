package pl.aibron.aigate.policy;

import java.time.Duration;
import java.util.regex.Pattern;

/** Parses the short duration format used in the policy file: 500ms, 30s, 15m, 1h, 1d. */
public final class Durations {

    private static final Pattern FORMAT = Pattern.compile("(\\d+)(ms|s|m|h|d)");

    private Durations() {
    }

    public static Duration parse(String text) {
        var matcher = FORMAT.matcher(text == null ? "" : text.trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("invalid duration '" + text + "', expected e.g. 30s, 15m, 1h");
        }
        long amount = Long.parseLong(matcher.group(1));
        return switch (matcher.group(2)) {
            case "ms" -> Duration.ofMillis(amount);
            case "s" -> Duration.ofSeconds(amount);
            case "m" -> Duration.ofMinutes(amount);
            case "h" -> Duration.ofHours(amount);
            default -> Duration.ofDays(amount);
        };
    }
}
