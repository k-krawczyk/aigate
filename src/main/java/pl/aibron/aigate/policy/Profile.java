package pl.aibron.aigate.policy;

/**
 * A strictness level. Clients reference a profile by name, so tightening every client in a group is a one-line edit.
 */
public record Profile(
        SemanticMode semanticCheck,
        Action onPii,
        Action onSecret,
        Action onSignatureMatch,
        RiskThresholds risk,
        GuardThresholds guardThresholds,
        Action onGuardError,
        SemanticMode outputCheck,
        Action onUnsafeOutput) {

    public enum SemanticMode { ALWAYS, ON_UNSURE, NEVER }

    public enum Action { ALLOW, REDACT, BLOCK }

    public record RiskThresholds(double unsureAbove, double blockAbove) { }

    public record GuardThresholds(double harmful, double injection) { }

    /**
     * The stricter of the two profiles on every setting separately: the harsher action, the more frequent guard
     * check, the lower thresholds, failing closed if either does. Used when an IdP group maps to a profile, so a
     * group can tighten a client but never loosen any single control.
     */
    public Profile stricterOf(Profile other) {
        return new Profile(
                semanticCheck.ordinal() <= other.semanticCheck.ordinal() ? semanticCheck : other.semanticCheck,
                harsher(onPii, other.onPii),
                harsher(onSecret, other.onSecret),
                harsher(onSignatureMatch, other.onSignatureMatch),
                new RiskThresholds(Math.min(risk.unsureAbove(), other.risk.unsureAbove()),
                        Math.min(risk.blockAbove(), other.risk.blockAbove())),
                new GuardThresholds(Math.min(guardThresholds.harmful(), other.guardThresholds.harmful()),
                        Math.min(guardThresholds.injection(), other.guardThresholds.injection())),
                harsher(onGuardError, other.onGuardError),
                outputCheck.ordinal() <= other.outputCheck.ordinal() ? outputCheck : other.outputCheck,
                harsher(onUnsafeOutput, other.onUnsafeOutput));
    }

    private static Action harsher(Action a, Action b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    public Profile {
        semanticCheck = semanticCheck == null ? SemanticMode.ON_UNSURE : semanticCheck;
        onPii = onPii == null ? Action.REDACT : onPii;
        onSecret = onSecret == null ? Action.BLOCK : onSecret;
        onSignatureMatch = onSignatureMatch == null ? Action.BLOCK : onSignatureMatch;
        risk = risk == null ? new RiskThresholds(0.3, 0.8) : risk;
        guardThresholds = guardThresholds == null ? new GuardThresholds(0.7, 0.7) : guardThresholds;
        onGuardError = onGuardError == null ? Action.BLOCK : onGuardError;
        outputCheck = outputCheck == null ? SemanticMode.ON_UNSURE : outputCheck;
        onUnsafeOutput = onUnsafeOutput == null ? Action.REDACT : onUnsafeOutput;
    }
}
