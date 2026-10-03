package pl.aibron.aigate.inspection;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;

import org.springframework.stereotype.Component;

/**
 * Runs every detector over a text. Detectors are ordered by specificity (secrets, IBAN, card, PESEL, ...), and a
 * later finding that overlaps an earlier one is dropped, so a 26-digit account number is reported once as IBAN
 * and not again as a card number.
 */
@Component
public class TextInspector {

    private final List<Detector> detectors;

    public TextInspector(List<Detector> detectors) {
        this.detectors = List.copyOf(detectors);
    }

    public List<Finding> scan(String text) {
        var accepted = new ArrayList<Finding>();
        if (text == null || text.isEmpty()) {
            return accepted;
        }
        for (var detector : detectors) {
            for (var finding : detector.scan(text)) {
                if (accepted.stream().noneMatch(finding::overlaps)) {
                    accepted.add(finding);
                }
            }
        }
        accepted.sort(Comparator.comparingInt(Finding::start));
        return accepted;
    }

    /** Replaces each selected finding with the text produced for it, working right to left so offsets stay valid. */
    public static String mask(String text, List<Finding> findings, Function<Finding, String> replacement) {
        var sb = new StringBuilder(text);
        findings.stream()
                .sorted(Comparator.comparingInt(Finding::start).reversed())
                .forEach(f -> sb.replace(f.start(), f.end(), replacement.apply(f)));
        return sb.toString();
    }

    /** Placeholder the model sees in a redacted request, so the sentence still makes sense to it. */
    public static String labelOf(Finding finding) {
        return "[" + finding.label() + "]";
    }

}
