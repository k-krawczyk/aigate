package pl.aibron.aigate.inspection.secret;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.Detector;
import pl.aibron.aigate.inspection.Finding;
import pl.aibron.aigate.inspection.FindingKind;

/**
 * Credentials with a recognisable vendor format. A prefix like AKIA or ghp_ is specific enough that a match is a
 * finding without further checks.
 */
@Component
@Order(1)
public class TokenFormatDetector implements Detector {

    private record Format(String id, Pattern pattern) { }

    private static final List<Format> FORMATS = List.of(
            new Format("secret.private_key", Pattern.compile(
                    "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
                            + "[\\s\\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)")),
            new Format("secret.aws_access_key", Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b")),
            new Format("secret.github_token", Pattern.compile("\\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\\b")),
            new Format("secret.openai_key", Pattern.compile("\\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\\b")),
            new Format("secret.slack_token", Pattern.compile("\\bxox[abprs]-[A-Za-z0-9-]{10,}\\b")),
            new Format("secret.google_api_key", Pattern.compile("\\bAIza[0-9A-Za-z_-]{35}\\b")),
            new Format("secret.stripe_key", Pattern.compile("\\b[sr]k_live_[0-9A-Za-z]{24,}\\b")),
            new Format("secret.jwt", Pattern.compile("\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}")),
            new Format("secret.connection_string", Pattern.compile(
                    "\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp|mssql)://[^\\s:/@]+:[^\\s@/]+@[^\\s/]+")));

    @Override
    public String id() {
        return "secret.token_format";
    }

    @Override
    public FindingKind kind() {
        return FindingKind.SECRET;
    }

    @Override
    public List<Finding> scan(String text) {
        var findings = new ArrayList<Finding>();
        for (var format : FORMATS) {
            var matcher = format.pattern().matcher(text);
            while (matcher.find()) {
                findings.add(new Finding(format.id(), FindingKind.SECRET, "SECRET", matcher.start(), matcher.end()));
            }
        }
        return findings;
    }
}
