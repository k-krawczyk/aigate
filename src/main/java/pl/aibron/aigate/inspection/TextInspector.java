package pl.aibron.aigate.inspection;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * Runs every detector over a text. Detectors are ordered by specificity (secrets, IBAN, card, PESEL, ...), and a
 * later finding that overlaps an earlier one is dropped, so a 26-digit account number is reported once as IBAN
 * and not again as a card number.
 */
@Component
public class TextInspector {

    private static final Pattern BASE64_RUN = Pattern.compile("[A-Za-z0-9+/]{16,}={0,2}");

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
        accepted.addAll(scanEncoded(text, accepted));
        accepted.sort(Comparator.comparingInt(Finding::start));
        return accepted;
    }

    /**
     * Base64 is the cheapest way to walk a secret past a pattern match. Runs that decode to readable text are
     * scanned again; a finding inside covers the whole encoded run.
     */
    private List<Finding> scanEncoded(String text, List<Finding> already) {
        var found = new ArrayList<Finding>();
        var matcher = BASE64_RUN.matcher(text);
        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            if (already.stream().anyMatch(f -> f.start() < end && start < f.end())) {
                continue;
            }
            var decoded = decodePrintable(matcher.group());
            if (decoded == null) {
                continue;
            }
            for (var detector : detectors) {
                var inner = detector.scan(decoded);
                if (!inner.isEmpty()) {
                    var f = inner.getFirst();
                    found.add(new Finding(f.detector() + ".base64", f.kind(), f.label(), start, end, f.category(),
                            f.owasp()));
                    break;
                }
            }
        }
        return found;
    }

    private static String decodePrintable(String candidate) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(candidate);
        } catch (IllegalArgumentException e) {
            return null;
        }
        try {
            var decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            long printable = decoded.chars().filter(c -> c >= 0x20 && c < 0x7f || c == '\n' || c == '\t').count();
            return printable >= decoded.length() * 0.9 ? decoded : null;
        } catch (CharacterCodingException e) {
            return null;
        }
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
