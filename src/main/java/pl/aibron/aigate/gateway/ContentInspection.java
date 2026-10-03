package pl.aibron.aigate.gateway;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.Finding;
import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.TextInspector;
import pl.aibron.aigate.policy.ClientSpec;
import pl.aibron.aigate.policy.Policy;
import pl.aibron.aigate.policy.Profile;
import pl.aibron.aigate.policy.Profile.Action;

/**
 * Deterministic content checks on the request. The profile decides per finding kind whether to let it through,
 * mask it, or stop the request.
 */
@Component
public class ContentInspection {

    private static final int EXCERPT_LENGTH = 300;

    private final TextInspector inspector;
    private final ToolGovernance tools;
    private final SystemPromptGuard promptGuard;

    public ContentInspection(TextInspector inspector, ToolGovernance tools, SystemPromptGuard promptGuard) {
        this.inspector = inspector;
        this.tools = tools;
        this.promptGuard = promptGuard;
    }

    public void inspectRequest(Exchange exchange) {
        var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
        var client = exchange.getProperty(ExchangeKeys.CLIENT, ClientSpec.class);
        var request = exchange.getProperty(ExchangeKeys.REQUEST, ObjectNode.class);
        var profile = exchange.getProperty(ExchangeKeys.PROFILE, Profile.class);

        var toolViolation = tools.checkRequest(request, client.tools());
        if (toolViolation.isPresent()) {
            var v = toolViolation.get();
            exchange.setProperty(ExchangeKeys.FINDINGS, List.of(v.finding()));
            markDecision(exchange, Decision.BLOCK, v.finding(), "request");
            throw new GatewayRejection(403, "tool_not_allowed", v.finding().category(), v.finding().owasp(),
                    v.message());
        }

        var texts = MessageText.ofRequest(request);
        var allFindings = new ArrayList<Finding>();
        var worst = Action.ALLOW;
        String excerpt = null;

        for (var text : texts) {
            var original = text.text();
            var findings = inspector.scan(original);
            allFindings.addAll(findings);
            for (var finding : findings) {
                var action = actionFor(profile, finding.kind());
                if (action.ordinal() > worst.ordinal()) {
                    worst = action;
                }
            }
            var toRedact = findings.stream().filter(f -> actionFor(profile, f.kind()) == Action.REDACT).toList();
            if (!toRedact.isEmpty()) {
                text.replace(TextInspector.mask(original, toRedact, TextInspector::labelOf));
            }
            if ("user".equals(text.role())) {
                // The audit excerpt is always fully masked, whatever the profile let through to the model.
                excerpt = TextInspector.mask(original, findings, TextInspector::labelOf);
            }
        }

        exchange.setProperty(ExchangeKeys.FINDINGS, allFindings);
        exchange.setProperty(ExchangeKeys.EXCERPT, excerpt == null ? null : truncate(excerpt));

        if (worst == Action.BLOCK) {
            var blocking = allFindings.stream().filter(f -> actionFor(profile, f.kind()) == Action.BLOCK).toList();
            var first = blocking.getFirst();
            markDecision(exchange, Decision.BLOCK, first, "request");
            throw new GatewayRejection(403, "content_blocked", first.category(), first.owasp(),
                    "Request blocked by policy: contains " + labels(blocking));
        }
        if (worst == Action.REDACT) {
            var first = allFindings.stream().filter(f -> actionFor(profile, f.kind()) == Action.REDACT)
                    .findFirst().orElseThrow();
            markDecision(exchange, Decision.REDACT, first, "request");
        } else {
            exchange.setProperty(ExchangeKeys.DECISION, Decision.ALLOW);
        }
        exchange.setProperty(ExchangeKeys.CANARY, promptGuard.plant(request));
        exchange.getMessage().setBody(request.toString());
    }

    static void markDecision(Exchange exchange, Decision decision, Finding finding, String direction) {
        exchange.setProperty(ExchangeKeys.DECISION, decision);
        exchange.setProperty(ExchangeKeys.CATEGORY, finding.category());
        exchange.setProperty(ExchangeKeys.OWASP, finding.owasp());
        exchange.setProperty(ExchangeKeys.DIRECTION, direction);
    }

    static Action actionFor(Profile profile, FindingKind kind) {
        return switch (kind) {
            case PII -> profile.onPii();
            case SECRET -> profile.onSecret();
            case SIGNATURE -> profile.onSignatureMatch();
            case TOOL, TOOL_ARGUMENT, PROMPT_LEAK, TOOL_INJECTION -> Action.BLOCK;
            case UNSAFE_OUTPUT -> profile.onUnsafeOutput();
        };
    }

    private static String labels(List<Finding> findings) {
        var labels = new LinkedHashSet<String>();
        findings.forEach(f -> labels.add(f.label()));
        return String.join(", ", labels);
    }

    private static String truncate(String text) {
        return text.length() <= EXCERPT_LENGTH ? text : text.substring(0, EXCERPT_LENGTH) + "...";
    }
}
