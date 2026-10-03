package pl.aibron.aigate.inspection.pii;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.RegexDetector;

/** Polish national ID: checksum plus a month field that must encode a real month in some century. */
@Component
@Order(30)
public class PeselDetector extends RegexDetector {

    private static final int[] WEIGHTS = {1, 3, 7, 9, 1, 3, 7, 9, 1, 3};

    public PeselDetector() {
        super("pii.pesel", FindingKind.PII, "PESEL", Pattern.compile("(?<!\\d)\\d{11}(?!\\d)"));
    }

    @Override
    protected boolean isValid(Matcher match) {
        return isValidPesel(match.group());
    }

    static boolean isValidPesel(String pesel) {
        int month = Integer.parseInt(pesel.substring(2, 4)) % 20;
        int day = Integer.parseInt(pesel.substring(4, 6));
        if (month < 1 || month > 12 || day < 1 || day > 31) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 10; i++) {
            sum += WEIGHTS[i] * (pesel.charAt(i) - '0');
        }
        return (10 - sum % 10) % 10 == pesel.charAt(10) - '0';
    }
}
