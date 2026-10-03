package pl.aibron.aigate.inspection.pii;

import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.RegexDetector;

@Component
@Order(40)
public class EmailDetector extends RegexDetector {

    public EmailDetector() {
        super("pii.email", FindingKind.PII, "EMAIL",
                Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"));
    }
}
