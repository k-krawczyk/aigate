package pl.aibron.aigate.inspection.pii;

import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.FindingKind;
import pl.aibron.aigate.inspection.RegexDetector;

/**
 * IBAN with ISO 13616 mod-97 check. Also accepts the Polish domestic NRB form (26 digits without the PL prefix),
 * which is how account numbers usually appear in Polish text.
 */
@Component
@Order(10)
public class IbanDetector extends RegexDetector {

    private static final BigInteger NINETY_SEVEN = BigInteger.valueOf(97);

    public IbanDetector() {
        super("pii.iban", FindingKind.PII, "IBAN", Pattern.compile(
                "\\b(?:[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?|\\d{2}(?: ?\\d{4}){6})\\b"));
    }

    @Override
    protected boolean isValid(Matcher match) {
        var compact = match.group().replace(" ", "");
        return isValidIban(Character.isDigit(compact.charAt(0)) ? "PL" + compact : compact);
    }

    static boolean isValidIban(String iban) {
        if (iban.length() < 15 || iban.length() > 34) {
            return false;
        }
        var rearranged = iban.substring(4) + iban.substring(0, 4);
        var numeric = new StringBuilder();
        for (char c : rearranged.toCharArray()) {
            numeric.append(Character.getNumericValue(c));
        }
        return new BigInteger(numeric.toString()).mod(NINETY_SEVEN).intValue() == 1;
    }
}
