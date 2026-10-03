package pl.aibron.aigate.inspection;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import pl.aibron.aigate.inspection.pii.EmailDetector;
import pl.aibron.aigate.inspection.pii.IbanDetector;
import pl.aibron.aigate.inspection.pii.PaymentCardDetector;
import pl.aibron.aigate.inspection.pii.PeselDetector;
import pl.aibron.aigate.inspection.pii.PhoneDetector;
import pl.aibron.aigate.inspection.pii.UsSsnDetector;
import pl.aibron.aigate.inspection.secret.PasswordAssignmentDetector;
import pl.aibron.aigate.inspection.secret.TokenFormatDetector;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Deterministic detectors: PII")
class PiiDetectorsTest {

    // Same order as Spring builds it from @Order.
    static final TextInspector INSPECTOR = new TextInspector(List.of(
            new TokenFormatDetector(), new PasswordAssignmentDetector(), new IbanDetector(),
            new PaymentCardDetector(), new PeselDetector(), new EmailDetector(), new PhoneDetector(),
            new UsSsnDetector()));

    @ParameterizedTest(name = "detected: {0}")
    @CsvSource(delimiter = '|', textBlock = """
            PESEL with valid checksum               | Klient 44051401359 prosi o kredyt      | pii.pesel
            PESEL born after 2000 (month + 20)      | PESEL: 02270803624                     | pii.pesel
            IBAN, Polish, spaced                    | PL61 1090 1014 0000 0712 1981 2874     | pii.iban
            IBAN, German                            | send to DE89370400440532013000 today   | pii.iban
            NRB, Polish domestic without prefix     | konto 61109010140000071219812874       | pii.iban
            payment card, Visa test number          | card 4111 1111 1111 1111 exp 12/29     | pii.payment_card
            payment card, dashed                    | 5500-0000-0000-0004                    | pii.payment_card
            email                                   | write to jan.kowalski@bank.pl please   | pii.email
            phone, Polish with country code         | call +48 601 234 567                   | pii.phone
            phone, Polish 3-3-3                     | tel. 601-234-567                       | pii.phone
            US SSN                                  | SSN 123-45-6789 on file                | pii.us_ssn
            """)
    void detects(String name, String text, String detector) {
        assertThat(INSPECTOR.scan(text)).extracting(Finding::detector).containsExactly(detector);
    }

    @ParameterizedTest(name = "ignored: {0}")
    @CsvSource(delimiter = '|', textBlock = """
            PESEL with wrong checksum               | Klient 44051401358 prosi o kredyt
            11 digits with impossible month         | order 44351401359
            IBAN with wrong checksum                | PL61 1090 1014 0000 0712 1981 2875
            card number failing Luhn                | card 4111 1111 1111 1112
            16 identical digits                     | ref 0000000000000000
            plain amount                            | the invoice total is 1234567 PLN
            bare 9-digit number                     | order number 601234567
            SSN in never-issued range               | id 666-45-6789
            ordinary sentence                       | What is the capital of Poland?
            """)
    void ignores(String name, String text) {
        assertThat(INSPECTOR.scan(text)).isEmpty();
    }

    @org.junit.jupiter.api.Test
    @DisplayName("overlap: a spaced account number is reported once as IBAN, not also as a card")
    void overlapResolvedToMostSpecific() {
        var findings = INSPECTOR.scan("przelew na 61 1090 1014 0000 0712 1981 2874");

        assertThat(findings).extracting(Finding::detector).containsExactly("pii.iban");
    }

    @org.junit.jupiter.api.Test
    @DisplayName("masking: findings are replaced by labels and the rest of the text is kept")
    void masks() {
        var text = "PESEL 44051401359, mail jan.kowalski@bank.pl";

        var masked = TextInspector.mask(text, INSPECTOR.scan(text), TextInspector::labelOf);

        assertThat(masked).isEqualTo("PESEL [PESEL], mail [EMAIL]");
    }
}
