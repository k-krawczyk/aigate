package pl.aibron.aigate.budget;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.GatewayTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The stub model reports 10 prompt + 5 completion tokens per call. gpt-4o costs 0.0025 / 0.01 USD per 1k tokens,
 * so each stubbed gpt-4o call costs USD 0.000075.
 */
@DisplayName("Budget and resource governance (OWASP LLM10)")
class BudgetGovernanceTest extends GatewayTestSupport {

    private static final String TINY_BUDGET_KEY = "aigate-tiny-budget-key";
    private static final String TINY_COST_KEY = "aigate-tiny-cost-key";
    private static final String LOOP_TEST_KEY = "aigate-loop-test-key";

    @Test
    @DisplayName("token budget: requests pass until 40 tokens are used, then 429")
    void tokenBudget() {
        assertThat(chat(TINY_BUDGET_KEY, "llama3.2:3b", "first question").statusCode()).isEqualTo(200);
        assertThat(chat(TINY_BUDGET_KEY, "llama3.2:3b", "second question").statusCode()).isEqualTo(200);
        assertThat(chat(TINY_BUDGET_KEY, "llama3.2:3b", "third question").statusCode()).isEqualTo(200);

        var response = chat(TINY_BUDGET_KEY, "llama3.2:3b", "fourth question");

        assertThat(response.statusCode()).isEqualTo(429);
        assertThat(response.body()).contains("\"code\":\"token_budget_exceeded\"", "\"type\":\"rate_limit_error\"");
    }

    @Test
    @DisplayName("cost budget: commercial model priced per token, blocked once USD 0.0001 is spent")
    void costBudget() {
        assertThat(chat(TINY_COST_KEY, "gpt-4o", "price check one").statusCode()).isEqualTo(200);
        assertThat(chat(TINY_COST_KEY, "gpt-4o", "price check two").statusCode()).isEqualTo(200);

        var response = chat(TINY_COST_KEY, "gpt-4o", "price check three");

        assertThat(response.statusCode()).isEqualTo(429);
        assertThat(response.body()).contains("\"code\":\"cost_budget_exceeded\"");
    }

    @Test
    @DisplayName("loop breaker: third near-identical request within 60 s is refused, different requests pass")
    void loopBreaker() {
        assertThat(chat(LOOP_TEST_KEY, "llama3.2:3b", "Check the status of order 1234 again").statusCode()).isEqualTo(200);
        assertThat(chat(LOOP_TEST_KEY, "llama3.2:3b", "check the status of order 1234 again!").statusCode()).isEqualTo(200);
        assertThat(chat(LOOP_TEST_KEY, "llama3.2:3b", "What are your opening hours on Sunday?").statusCode()).isEqualTo(200);

        var response = chat(LOOP_TEST_KEY, "llama3.2:3b", "Check the status of order 1234 again");

        assertThat(response.statusCode()).isEqualTo(429);
        assertThat(response.body()).contains("\"code\":\"loop_detected\"", "\"category\":\"unbounded_consumption\"");
    }

    @Test
    @DisplayName("allowed: ordinary multi-turn chat with growing history does not trip the loop breaker")
    void multiTurnIsNotALoop() {
        var history = new StringBuilder();
        for (int turn = 1; turn <= 4; turn++) {
            history.append("""
                    {"role":"user","content":"Tell me fact number %d about Krakow"},
                    {"role":"assistant","content":"Here is a long and detailed fact about Krakow and its history."},
                    """.formatted(turn));
            var body = """
                    {"model":"llama3.2:3b","messages":[%s{"role":"user","content":"And what about topic %s?"}]}
                    """.formatted(history, switch (turn) {
                        case 1 -> "Wawel castle";
                        case 2 -> "the salt mine in Wieliczka";
                        case 3 -> "Nowa Huta architecture";
                        default -> "obwarzanek pretzels";
                    });
            assertThat(post(LOOP_TEST_KEY, body).statusCode()).as("turn %d", turn).isEqualTo(200);
        }
    }
}
