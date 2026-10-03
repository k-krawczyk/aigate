package pl.aibron.aigate.signatures;

import java.io.IOException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.inspection.TextInspector;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Signatures: every occurrence is found")
class SignatureDetectorTest {

    @Test
    @DisplayName("a payload repeated twice is reported twice, so redaction masks both copies")
    void allOccurrences() throws IOException {
        var detector = new SignatureDetector(new SignatureFeed(null, ""));
        var text = "a: !!python/object/apply:os.system ['id'] and b: !!python/object/apply:os.system ['ls']";

        var findings = detector.scan(text);
        var masked = TextInspector.mask(text, findings, TextInspector::labelOf);

        assertThat(findings).hasSize(2);
        assertThat(masked).doesNotContain("!!python/object");
    }
}
