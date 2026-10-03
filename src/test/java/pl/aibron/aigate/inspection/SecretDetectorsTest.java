package pl.aibron.aigate.inspection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static pl.aibron.aigate.inspection.PiiDetectorsTest.INSPECTOR;

@DisplayName("Deterministic detectors: secrets")
class SecretDetectorsTest {

    @ParameterizedTest(name = "detected: {0}")
    @CsvSource(delimiter = '|', textBlock = """
            AWS access key id               | aws_access_key_id = AKIAIOSFODNN7EXAMPLE                             | secret.aws_access_key
            GitHub personal token           | token ghp_1A2b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8r                      | secret.github_token
            OpenAI-style key                | OPENAI=sk-proj-Ab12Cd34Ef56Gh78Ij90Kl12                              | secret.openai_key
            Slack bot token                 | xoxb-123456789012-abcdefABCDEF                                       | secret.slack_token
            Google API key                  | key=AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q                          | secret.google_api_key
            JWT                             | Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U | secret.jwt
            database URL with password      | jdbc to postgres://app:S3cr3tPass@db.internal:5432/core              | secret.connection_string
            random-looking password         | password: Xk9#mQ2$vL7pR4!w                                           | secret.password_assignment
            """)
    void detects(String name, String text, String detector) {
        assertThat(INSPECTOR.scan(text)).extracting(Finding::detector).contains(detector);
    }

    @Test
    @DisplayName("detected: PEM private key block, masked as a whole")
    void privateKey() {
        var text = "here is my key\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----\nthanks";

        var masked = TextInspector.mask(text, INSPECTOR.scan(text), TextInspector::labelOf);

        assertThat(masked).isEqualTo("here is my key\n[SECRET]\nthanks");
    }

    @Test
    @DisplayName("masking: only the value of a password assignment is masked")
    void passwordValueOnly() {
        var text = "password: Xk9#mQ2$vL7pR4!w";

        assertThat(TextInspector.mask(text, INSPECTOR.scan(text), TextInspector::labelOf))
                .isEqualTo("password: [SECRET]");
    }

    @ParameterizedTest(name = "ignored: {0}")
    @CsvSource(delimiter = '|', textBlock = """
            low-entropy example password    | set password: aaaaaaaa in the config
            the word token in prose         | how do I refresh an access token in OAuth?
            AWS docs mention without key    | where do I find my AKIA key in the console?
            URL without credentials         | see postgres://db.internal:5432/core
            """)
    void ignores(String name, String text) {
        assertThat(INSPECTOR.scan(text)).isEmpty();
    }
}
