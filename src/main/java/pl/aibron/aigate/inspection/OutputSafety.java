package pl.aibron.aigate.inspection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * Markup in a model answer that acts on its own once a chat client renders it (OWASP LLM05): images that call
 * out to a server with data in the URL (the classic way an indirect injection exfiltrates a conversation),
 * scripts, frames, javascript: URLs and inline event handlers.
 *
 * <p>Anything inside markdown code (fenced blocks or inline backticks) is ignored: it is displayed as text, and an
 * answer explaining XSS must not be censored.
 */
@Component
public class OutputSafety {

    private record Rule(String id, Pattern pattern) { }

    private static final List<Rule> RULES = List.of(
            new Rule("output.exfil_markdown_image",
                    Pattern.compile("!\\[[^\\]]*\\]\\(\\s*<?https?://[^)\\s]*\\?[^)\\s]*=[^)\\s]*>?(?:\\s+\"[^\"]*\")?\\s*\\)")),
            new Rule("output.exfil_html_image",
                    Pattern.compile("(?i)<img\\b[^>]*\\bsrc\\s*=\\s*[\"']?https?://[^\"'\\s>]*\\?[^\"'\\s>]*=[^>]*>")),
            new Rule("output.script", Pattern.compile("(?is)<script\\b.*?(?:</script\\s*>|$)")),
            new Rule("output.frame", Pattern.compile("(?is)<(?:iframe|frame|object|embed)\\b[^>]*>(?:.*?</(?:iframe|frame|object)\\s*>)?")),
            new Rule("output.javascript_url", Pattern.compile("(?i)\\bjavascript\\s*:[^\\s)\"'>]*")),
            new Rule("output.event_handler", Pattern.compile("(?i)<[a-z][a-z0-9]*\\b[^>]*\\son[a-z]+\\s*=[^>]*>")));

    private static final Pattern CODE = Pattern.compile("(?s)```.*?(?:```|$)|`[^`\\n]+`");

    public List<Finding> scan(String text) {
        var findings = new ArrayList<Finding>();
        if (text == null || text.isEmpty()) {
            return findings;
        }
        var code = new ArrayList<int[]>();
        var codeMatcher = CODE.matcher(text);
        while (codeMatcher.find()) {
            code.add(new int[] {codeMatcher.start(), codeMatcher.end()});
        }
        for (var rule : RULES) {
            var matcher = rule.pattern().matcher(text);
            while (matcher.find()) {
                int start = matcher.start();
                int end = matcher.end();
                boolean inCode = code.stream().anyMatch(c -> start >= c[0] && end <= c[1]);
                var finding = new Finding(rule.id(), FindingKind.UNSAFE_OUTPUT, "UNSAFE_OUTPUT", start, end);
                if (!inCode && findings.stream().noneMatch(finding::overlaps)) {
                    findings.add(finding);
                }
            }
        }
        return findings;
    }
}
