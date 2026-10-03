package pl.aibron.aigate.signatures;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Signature feed: validation")
class SignatureSetTest {

    @Test
    @DisplayName("valid: the published feed/signatures.json and the bundled copy are identical and parse")
    void publishedFeedParses() throws Exception {
        var published = Files.readString(Path.of("feed/signatures.json"));
        var bundled = Files.readString(Path.of("src/main/resources/signatures/bundled.json"));

        assertThat(SignatureSet.parse(published, "test").signatures()).hasSizeGreaterThanOrEqualTo(14);
        assertThat(bundled).isEqualTo(published);
    }

    @Test
    @DisplayName("rejected: duplicate signature id")
    void duplicateId() {
        var json = """
                {"version":"x","signatures":[
                  {"id":"A","category":"c","pattern":"a"},{"id":"A","category":"c","pattern":"b"}]}
                """;

        assertThatThrownBy(() -> SignatureSet.parse(json, "test")).hasMessageContaining("duplicate");
    }

    @Test
    @DisplayName("rejected: empty feed would remove all protection")
    void emptyFeed() {
        assertThatThrownBy(() -> SignatureSet.parse("{\"version\":\"x\",\"signatures\":[]}", "test"))
                .hasMessageContaining("no signatures");
    }
}
