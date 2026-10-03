package pl.aibron.aigate.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import pl.aibron.aigate.policy.Profile.Action;
import pl.aibron.aigate.policy.Profile.GuardThresholds;
import pl.aibron.aigate.policy.Profile.RiskThresholds;
import pl.aibron.aigate.policy.Profile.SemanticMode;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Policy: merging a client profile with an IdP group profile")
class ProfileMergeTest {

    private static final Profile BALANCED = new Profile(SemanticMode.ON_UNSURE, Action.REDACT, Action.BLOCK,
            Action.BLOCK, new RiskThresholds(0.3, 0.8), new GuardThresholds(0.7, 0.7), Action.BLOCK,
            SemanticMode.ON_UNSURE, Action.REDACT, Profile.ToolInjectionAction.QUARANTINE);
    private static final Profile STRICT_PII_LAX_REST = new Profile(SemanticMode.NEVER, Action.BLOCK, Action.ALLOW,
            Action.ALLOW, new RiskThresholds(1.0, 1.0), new GuardThresholds(0.9, 0.9), Action.ALLOW,
            SemanticMode.NEVER, Action.ALLOW, Profile.ToolInjectionAction.ALLOW);

    @Test
    @DisplayName("every setting takes the stricter value, so no single control is loosened")
    void perSetting() {
        var merged = BALANCED.stricterOf(STRICT_PII_LAX_REST);

        assertThat(merged.onPii()).isEqualTo(Action.BLOCK);
        assertThat(merged.onSecret()).isEqualTo(Action.BLOCK);
        assertThat(merged.onSignatureMatch()).isEqualTo(Action.BLOCK);
        assertThat(merged.semanticCheck()).isEqualTo(SemanticMode.ON_UNSURE);
        assertThat(merged.risk()).isEqualTo(new RiskThresholds(0.3, 0.8));
        assertThat(merged.guardThresholds()).isEqualTo(new GuardThresholds(0.7, 0.7));
        assertThat(merged.onGuardError()).isEqualTo(Action.BLOCK);
        assertThat(merged.outputCheck()).isEqualTo(SemanticMode.ON_UNSURE);
        assertThat(merged.onUnsafeOutput()).isEqualTo(Action.REDACT);
        assertThat(merged.onToolInjection()).isEqualTo(Profile.ToolInjectionAction.QUARANTINE);
    }

    @Test
    @DisplayName("merging is symmetric and merging with itself changes nothing")
    void symmetric() {
        assertThat(BALANCED.stricterOf(STRICT_PII_LAX_REST)).isEqualTo(STRICT_PII_LAX_REST.stricterOf(BALANCED));
        assertThat(BALANCED.stricterOf(BALANCED)).isEqualTo(BALANCED);
    }
}
