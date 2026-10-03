package pl.aibron.aigate.gateway;

import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.camel.Exchange;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.Finding;
import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.TextInspector;
import pl.aibron.aigate.policy.ClientSpec;
import pl.aibron.aigate.policy.Policy;
import pl.aibron.aigate.policy.Profile.Action;

/**
 * Checks the model's answer before the client sees it: leaked PII or secrets, system prompt leakage, and tool calls
 * outside the client's allowlist. Redaction here is silent: the client gets masked text with no marker, and the
 * audit event records what was masked.
 */
@Component
public class ResponseInspection {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SILENT_MASK = "****";

    private final TextInspector inspector;
    private final ToolGovernance tools;
    private final SystemPromptGuard promptGuard;

    public ResponseInspection(TextInspector inspector, ToolGovernance tools, SystemPromptGuard promptGuard) {
        this.inspector = inspector;
        this.tools = tools;
        this.promptGuard = promptGuard;
    }

    public void inspectResponse(Exchange exchange) {
        var status = exchange.getMessage().getHeader(Exchange.HTTP_RESPONSE_CODE, 200, Integer.class);
        if (status != 200) {
            return;
        }
        ObjectNode response;
        try {
            if (!(JSON.readTree(exchange.getMessage().getBody(String.class)) instanceof ObjectNode parsed)) {
                return;
            }
            response = parsed;
        } catch (JsonProcessingException e) {
            return;
        }
        var policy = exchange.getProperty(ExchangeKeys.POLICY, Policy.class);
        var client = exchange.getProperty(ExchangeKeys.CLIENT, ClientSpec.class);
        var profile = policy.profileOf(client);
        var planted = exchange.getProperty(ExchangeKeys.CANARY, SystemPromptGuard.Planted.class);

        var toolViolation = tools.checkResponse(response, client.tools());
        if (toolViolation.isPresent()) {
            var v = toolViolation.get();
            block(exchange, v.finding(), "Model response blocked: " + v.message());
        }

        boolean redacted = false;
        for (var text : MessageText.ofResponse(response)) {
            var answer = text.text();
            if (promptGuard.leaked(planted, answer)) {
                block(exchange, new Finding("output.system_prompt_leak", FindingKind.PROMPT_LEAK, "SYSTEM_PROMPT", 0, 0),
                        "Model response blocked: it reveals the system prompt");
            }
            var findings = inspector.scan(answer);
            if (findings.isEmpty()) {
                continue;
            }
            addFindings(exchange, findings);
            var blocking = findings.stream()
                    .filter(f -> ContentInspection.actionFor(profile, f.kind()) == Action.BLOCK).toList();
            if (!blocking.isEmpty()) {
                block(exchange, blocking.getFirst(),
                        "Model response blocked by policy: contains " + blocking.getFirst().label());
            }
            var toRedact = findings.stream()
                    .filter(f -> ContentInspection.actionFor(profile, f.kind()) == Action.REDACT).toList();
            if (!toRedact.isEmpty()) {
                text.replace(TextInspector.mask(answer, toRedact, f -> SILENT_MASK));
                if (!redacted && exchange.getProperty(ExchangeKeys.DECISION) != Decision.REDACT) {
                    ContentInspection.markDecision(exchange, Decision.REDACT, toRedact.getFirst(), "response");
                }
                redacted = true;
            }
        }
        if (redacted) {
            exchange.getMessage().setBody(response.toString());
        }
    }

    private static void block(Exchange exchange, Finding finding, String message) {
        addFindings(exchange, List.of(finding));
        ContentInspection.markDecision(exchange, Decision.BLOCK, finding, "response");
        throw new GatewayRejection(403, "response_blocked", finding.category(), finding.owasp(), message);
    }

    @SuppressWarnings("unchecked")
    private static void addFindings(Exchange exchange, List<Finding> findings) {
        var existing = (List<Finding>) exchange.getProperty(ExchangeKeys.FINDINGS, List.class);
        var merged = new java.util.ArrayList<Finding>(existing == null ? List.of() : existing);
        merged.addAll(findings);
        exchange.setProperty(ExchangeKeys.FINDINGS, merged);
    }
}
