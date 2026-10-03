package pl.aibron.aigate.inspection.pii;

import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.RegexDetector;

/** US SSN in its dashed form, excluding ranges the SSA never issues. */
@Component
@Order(60)
public class UsSsnDetector extends RegexDetector {

    public UsSsnDetector() {
        super("pii.us_ssn", FindingKind.PII, "SSN",
                Pattern.compile("\\b(?!000|666|9\\d\\d)\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b"));
    }
}
