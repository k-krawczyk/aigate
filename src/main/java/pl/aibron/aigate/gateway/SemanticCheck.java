package pl.aibron.aigate.gateway;

import java.util.Locale;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.RiskScorer;
import pl.aibron.aigate.policy.ClientSpec;
import pl.aibron.aigate.policy.Policy;
import pl.aibron.aigate.policy.Profile;
import pl.aibron.aigate.policy.Profile.Action;

/**
 * Hybrid step: the rule-based risk score settles clear cases in microseconds, and only the grey zone (or every
 * request, if the profile says so) pays for the guard models.
 */
@Component
public class SemanticCheck {

    public static final String INJECTION = "prompt_injection";
    public static final String HARMFUL = "harmful_content";

    private static final Logger log = LoggerFactory.getLogger(SemanticCheck.class);

    private final RiskScorer riskScorer;
    private final SemanticGuard guard;

    public SemanticCheck(RiskScorer riskScorer, SemanticGuard guard) {
        this.riskScorer = riskScorer;
        this.guard = guard;
    }

    public void evaluate(Exchange exchange) {
        var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
        var client = exchange.getProperty(ExchangeKeys.CLIENT, ClientSpec.class);
        var request = exchange.getProperty(ExchangeKeys.REQUEST, ObjectNode.class);
        var profile = exchange.getProperty(ExchangeKeys.PROFILE, Profile.class);
        var text = MessageText.conversationInput(request);

        var risk = riskScorer.assess(text);
        exchange.setProperty(ExchangeKeys.RISK_SCORE, risk.score());
        var signals = risk.signals().stream().map(RiskScorer.Signal::id).collect(Collectors.joining(","));
        note(exchange, risk.signals().isEmpty() ? null : "risk " + format(risk.score()) + " [" + signals + "]");

        if (risk.score() >= profile.risk().blockAbove() && risk.score() > 0) {
            block(exchange, INJECTION, "LLM01", signals,
                    "Request blocked: prompt injection indicators (risk " + format(risk.score()) + ")");
        }
        boolean unsure = risk.score() >= profile.risk().unsureAbove() && risk.score() > 0;
        if (profile.semanticCheck() == Profile.SemanticMode.NEVER
                || profile.semanticCheck() == Profile.SemanticMode.ON_UNSURE && !unsure) {
            return;
        }
        if (unsure && exchange.getProperty(ExchangeKeys.DECISION) == Decision.ALLOW) {
            exchange.setProperty(ExchangeKeys.DECISION, Decision.UNSURE);
        }

        SemanticGuard.Verdict verdict;
        try {
            verdict = guard.evaluate(text);
        } catch (Exception e) {
            log.warn("Guard models unavailable: {}", e.toString());
            note(exchange, "guard error: " + e.getClass().getSimpleName());
            if (profile.onGuardError() == Action.BLOCK) {
                block(exchange, "guard_unavailable", null, "semantic.unavailable",
                        "Request blocked: semantic check unavailable and the policy fails closed");
            }
            settle(exchange);
            return;
        }
        note(exchange, "guards harmful " + format(verdict.harmScore())
                + (verdict.harmCategory() == null ? "" : " (" + verdict.harmCategory() + ")")
                + ", injection " + format(verdict.injectionScore()) + ", " + verdict.millis() + " ms");

        // Harmful content first: its hazard category says more than "injection" when both guards fire.
        if (verdict.harmScore() >= profile.guardThresholds().harmful()) {
            block(exchange, HARMFUL, null, "semantic.harmful",
                    "Request blocked: harmful content" + (verdict.harmCategory() == null ? ""
                            : ", " + verdict.harmCategory()) + " (guard score " + format(verdict.harmScore()) + ")");
        }
        if (verdict.injectionScore() >= profile.guardThresholds().injection()) {
            block(exchange, INJECTION, "LLM01", "semantic.injection",
                    "Request blocked: prompt injection (guard score " + format(verdict.injectionScore()) + ")");
        }
        settle(exchange);
    }

    /** The guards cleared an UNSURE request. */
    private static void settle(Exchange exchange) {
        if (exchange.getProperty(ExchangeKeys.DECISION) == Decision.UNSURE) {
            exchange.setProperty(ExchangeKeys.DECISION, Decision.ALLOW);
        }
    }

    private static void block(Exchange exchange, String category, String owasp, String rule, String message) {
        exchange.setProperty(ExchangeKeys.DECISION, Decision.BLOCK);
        exchange.setProperty(ExchangeKeys.CATEGORY, category);
        exchange.setProperty(ExchangeKeys.OWASP, owasp);
        exchange.setProperty(ExchangeKeys.DIRECTION, "request");
        exchange.setProperty(ExchangeKeys.SEMANTIC_RULE, rule);
        throw new GatewayRejection(403, category, category, owasp, message);
    }

    private static void note(Exchange exchange, String text) {
        if (text == null) {
            return;
        }
        var previous = exchange.getProperty(ExchangeKeys.SEMANTIC_NOTE, String.class);
        exchange.setProperty(ExchangeKeys.SEMANTIC_NOTE, previous == null ? text : previous + "; " + text);
    }

    private static String format(double score) {
        return String.format(Locale.ROOT, "%.2f", score);
    }
}
