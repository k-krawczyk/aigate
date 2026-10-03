package pl.aibron.aigate.signatures;

import java.util.ArrayList;
import java.util.List;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import pl.aibron.aigate.inspection.Detector;
import pl.aibron.aigate.inspection.Finding;
import pl.aibron.aigate.inspection.FindingKind;

/** Runs the current feed over a text. Ordered first: a known exploit is the most specific finding there is. */
@Component
@Order(0)
public class SignatureDetector implements Detector {

    private final SignatureFeed feed;

    public SignatureDetector(SignatureFeed feed) {
        this.feed = feed;
    }

    @Override
    public String id() {
        return "signature";
    }

    @Override
    public FindingKind kind() {
        return FindingKind.SIGNATURE;
    }

    @Override
    public List<Finding> scan(String text) {
        var findings = new ArrayList<Finding>();
        for (var compiled : feed.current().signatures()) {
            var matcher = compiled.pattern().matcher(text);
            if (matcher.find()) {
                var s = compiled.signature();
                findings.add(new Finding("signature." + s.id(), FindingKind.SIGNATURE, s.id(), matcher.start(),
                        matcher.end(), s.category(), s.owasp()));
            }
        }
        return findings;
    }
}
