package pl.aibron.aigate.policy;

import java.time.Duration;

public record Budgets(
        String window,
        Long maxTokens,
        Double maxCostUsd,
        Long maxModelSeconds,
        LoopBreaker loopBreaker) {

    public static final Budgets NONE = new Budgets("1h", null, null, null, null);

    public record LoopBreaker(int maxSimilarRequests, String within, double similarity) {

        public Duration withinDuration() {
            return Durations.parse(within);
        }
    }

    public Duration windowDuration() {
        return Durations.parse(window);
    }

    Budgets withDefaults(Budgets global) {
        return new Budgets(
                window != null ? window : global.window(),
                maxTokens != null ? maxTokens : global.maxTokens(),
                maxCostUsd != null ? maxCostUsd : global.maxCostUsd(),
                maxModelSeconds != null ? maxModelSeconds : global.maxModelSeconds(),
                loopBreaker != null ? loopBreaker : global.loopBreaker());
    }
}
