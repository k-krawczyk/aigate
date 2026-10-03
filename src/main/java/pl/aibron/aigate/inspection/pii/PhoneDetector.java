package pl.aibron.aigate.inspection.pii;

import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.RegexDetector;

/**
 * Phone numbers written the way people write them: with a country code, or as Polish 3-3-3 groups.
 * Bare 9-digit runs are not matched; they are far more often IDs or amounts.
 */
@Component
@Order(50)
public class PhoneDetector extends RegexDetector {

    public PhoneDetector() {
        super("pii.phone", FindingKind.PII, "PHONE", Pattern.compile(
                "(?<![\\w+])(?:\\+\\d{1,3}[ -]?(?:\\(?\\d{1,4}\\)?[ -]?){2,4}\\d{2,4}|\\d{3}[ -]\\d{3}[ -]\\d{3})(?![\\w-])"));
    }
}
