package pl.aibron.aigate.gateway;

import java.util.Locale;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.policy.Profile;
import pl.aibron.aigate.policy.Profile.Action;

/**
 * Llama Guard on the model's answer, for the case the input checks missed: a jailbreak that worked and produced
 * harmful content no rule recognises. Runs per the profile's output_check: always; on_unsure, when the request was
 * in the grey zone or the answer carried active markup; never.
 */
@Component
public class OutputSemanticCheck {

    private static final Logger log = LoggerFactory.getLogger(OutputSemanticCheck.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final SemanticGuard guard;

    public OutputSemanticCheck(SemanticGuard guard) {
        this.guard = guard;
    }

    public void evaluate(Exchange exchange) throws Exception {
        var status = exchange.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE, 200, Integer.class);
        var profile = exchange.getProperty(ExchangeKeys.PROFILE, Profile.class);
        if (status != 200 || profile == null || !wanted(exchange, profile)) {
            return;
        }
        if (!(JSON.readTree(exchange.getMessage().getBody(String.class)) instanceof ObjectNode response)) {
            return;
        }
        var answer = new StringBuilder();
        MessageText.ofResponse(response).forEach(t -> answer.append(t.text()).append('\n'));
        if (answer.toString().isBlank()) {
            return;
        }
        var request = exchange.getProperty(ExchangeKeys.REQUEST, ObjectNode.class);

        SemanticGuard.Verdict verdict;
        try {
            verdict = guard.evaluateAnswer(MessageText.newInput(request), answer.toString());
        } catch (Exception e) {
            log.warn("Guard model unavailable for the answer check: {}", e.toString());
            if (profile.onGuardError() == Action.BLOCK) {
                block(exchange, "guard_unavailable", "semantic.output_unavailable",
                        "Model response blocked: answer check unavailable and the policy fails closed");
            }
            return;
        }
        if (verdict.harmScore() >= profile.guardThresholds().harmful()) {
            block(exchange, SemanticCheck.HARMFUL, "semantic.harmful_output",
                    "Model response blocked: harmful content" + (verdict.harmCategory() == null ? ""
                            : ", " + verdict.harmCategory()) + String.format(Locale.ROOT, " (guard score %.2f)",
                            verdict.harmScore()));
        }
    }

    private static boolean wanted(Exchange exchange, Profile profile) {
        return switch (profile.outputCheck()) {
            case ALWAYS -> true;
            case NEVER -> false;
            case ON_UNSURE -> Boolean.TRUE.equals(exchange.getProperty(ExchangeKeys.INPUT_UNSURE, Boolean.class))
                    || Boolean.TRUE.equals(exchange.getProperty(ExchangeKeys.OUTPUT_SIGNALS, Boolean.class));
        };
    }

    private static void block(Exchange exchange, String category, String rule, String message) {
        exchange.setProperty(ExchangeKeys.DECISION, Decision.BLOCK);
        exchange.setProperty(ExchangeKeys.CATEGORY, category);
        exchange.setProperty(ExchangeKeys.OWASP, null);
        exchange.setProperty(ExchangeKeys.DIRECTION, "response");
        exchange.setProperty(ExchangeKeys.SEMANTIC_RULE, rule);
        throw new GatewayRejection(403, "response_blocked", category, message);
    }
}
