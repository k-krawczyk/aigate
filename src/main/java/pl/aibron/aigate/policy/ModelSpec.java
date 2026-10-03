package pl.aibron.aigate.policy;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Prices are in USD per 1000 tokens. Local models get an estimated compute cost so that budgets treat them the same way.
 */
public record ModelSpec(
        String name,
        Kind kind,
        @JsonProperty("price_per_1k_input") double pricePer1kInput,
        @JsonProperty("price_per_1k_output") double pricePer1kOutput) {

    public enum Kind { LOCAL, COMMERCIAL }

    public double cost(long inputTokens, long outputTokens) {
        return inputTokens / 1000.0 * pricePer1kInput + outputTokens / 1000.0 * pricePer1kOutput;
    }
}
