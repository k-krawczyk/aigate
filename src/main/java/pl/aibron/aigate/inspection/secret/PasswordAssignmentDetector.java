package pl.aibron.aigate.inspection.secret;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.RegexDetector;

/**
 * "password: X" style assignments. Only the value is masked, and only when it looks random enough to be a real
 * credential; "password: changeme" in a how-to question is not worth blocking.
 */
@Component
@Order(2)
public class PasswordAssignmentDetector extends RegexDetector {

    private static final double MIN_ENTROPY_BITS_PER_CHAR = 3.0;

    public PasswordAssignmentDetector() {
        super("secret.password_assignment", FindingKind.SECRET, "SECRET", Pattern.compile(
                "(?i)\\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
                        + "\\b[\"']?\\s*[:=]\\s*[\"']?([^\\s\"',;]{8,})"));
    }

    @Override
    protected int sensitiveGroup() {
        return 1;
    }

    @Override
    protected boolean isValid(Matcher match) {
        return shannonEntropy(match.group(1)) >= MIN_ENTROPY_BITS_PER_CHAR;
    }

    static double shannonEntropy(String value) {
        var counts = new HashMap<Integer, Integer>();
        value.codePoints().forEach(c -> counts.merge(c, 1, Integer::sum));
        double entropy = 0;
        for (int count : counts.values()) {
            double p = (double) count / value.length();
            entropy -= p * Math.log(p) / Math.log(2);
        }
        return entropy;
    }
}
