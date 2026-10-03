package pl.aibron.aigate.inspection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * Signs that data returned by a tool, or a tool's description, talks to the assistant instead of carrying
 * information. In user text these phrases can be innocent; in a search result, a web page, a file or an MCP tool
 * description they have no business being there, so a single one is enough.
 */
@Component
public class ToolDataRules {

    private record Rule(String id, Pattern pattern) { }

    private static final List<Rule> RULES = List.of(
            new Rule("tool.addressed_to_ai", Pattern.compile(
                    "(?iU)\\b(?:(?:note|message|instruction|attention|reminder)s?\\s+(?:to|for)\\s+(?:the\\s+|any\\s+)?(?:ai|assistant|llm|language model|model|agent|chatbot)s?"
                            + "|(?:ai|llm|language)\\s*(?:models?|assistants?|agents?)?\\s+(?:reading|processing|summari[sz]ing|that read)"
                            + "|dear\\s+(?:ai|assistant)|asystenc\\w*\\s+ai)\\b")),
            new Rule("tool.credential_lure", Pattern.compile(
                    "(?iU)\\b(?:re-?enter|confirm|verify|provide|submit|update|potwierd\\w*|poda\\w*)\\b.{0,40}\\b(?:password|pin|passcode|credentials|login|card (?:details|number)|hasł\\w*|dane karty)\\b.{0,60}(?:https?://|\\bat\\s+\\S+\\.\\S+|\\bna stronie\\b)")),
            new Rule("tool.exfiltrate_context", Pattern.compile(
                    "(?i)\\b(?:include|pass|send|attach|append|forward|bcc|copy)\\b.{0,40}\\b(?:full |entire |whole )?(?:conversation|chat history|message history|system prompt|context window|previous messages)")),
            new Rule("tool.steer_tool_call", Pattern.compile(
                    "(?i)\\b(?:call|invoke|use|run|execute)\\s+(?:the\\s+)?[a-z_][a-z0-9_]*\\s+(?:tool|function)\\b.{0,60}\\b(?:now|immediately|without|do not ask|before)")),
            new Rule("tool.concealment", Pattern.compile(
                    "(?i)\\b(?:do not|don't|never)\\s+(?:tell|mention|show|inform|reveal|disclose)\\b.{0,30}\\b(?:the\\s+)?user|\\bwithout\\s+(?:asking|confirmation|telling)")),
            new Rule("tool.read_secrets", Pattern.compile(
                    "(?i)(?:~/\\.ssh|id_rsa|\\.env\\b|mcp\\.json|\\.aws/credentials|\\.npmrc|\\.git-credentials)")));

    private final RiskScorer riskScorer;

    public ToolDataRules(RiskScorer riskScorer) {
        this.riskScorer = riskScorer;
    }

    /** Rule ids that matched: the tool-data rules above plus the injection rules that apply to any text. */
    public List<String> signals(String text) {
        var signals = new ArrayList<String>();
        if (text == null || text.isEmpty()) {
            return signals;
        }
        for (var rule : RULES) {
            if (rule.pattern().matcher(text).find()) {
                signals.add(rule.id());
            }
        }
        for (var signal : riskScorer.assess(text).signals()) {
            if (signal.id().startsWith("injection.") || signal.id().startsWith("exfiltration.")
                    || signal.id().startsWith("obfuscation.invisible")) {
                signals.add(signal.id());
            }
        }
        return signals;
    }
}
