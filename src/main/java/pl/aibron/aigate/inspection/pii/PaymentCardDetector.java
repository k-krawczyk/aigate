package pl.aibron.aigate.inspection.pii;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.RegexDetector;

@Component
@Order(20)
public class PaymentCardDetector extends RegexDetector {

    public PaymentCardDetector() {
        super("pii.payment_card", FindingKind.PII, "CARD", Pattern.compile("(?<![\\d-])(?:\\d[ -]?){12,18}\\d(?![\\d-])"));
    }

    @Override
    protected boolean isValid(Matcher match) {
        var digits = digitsOnly(match.group());
        return digits.length() >= 13 && digits.length() <= 19 && !digits.matches("(\\d)\\1+") && luhn(digits);
    }

    static boolean luhn(String digits) {
        int sum = 0;
        boolean doubleIt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (doubleIt) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }
}
