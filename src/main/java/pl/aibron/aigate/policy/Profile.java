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
        Action onGuardError) {

    public enum SemanticMode { ALWAYS, ON_UNSURE, NEVER }

    public enum Action { ALLOW, REDACT, BLOCK }

    public record RiskThresholds(double unsureAbove, double blockAbove) { }

    public record GuardThresholds(double harmful, double injection) { }

    /**
     * Higher is stricter: first by how PII is treated, then by how often the guard models are asked. Used when an
     * IdP group maps to a profile, so a group can tighten a client but never loosen it.
     */
    public int strictness() {
        return onPii.ordinal() * 10 + (SemanticMode.values().length - 1 - semanticCheck.ordinal());
    }

    public Profile {
        semanticCheck = semanticCheck == null ? SemanticMode.ON_UNSURE : semanticCheck;
        onPii = onPii == null ? Action.REDACT : onPii;
        onSecret = onSecret == null ? Action.BLOCK : onSecret;
        onSignatureMatch = onSignatureMatch == null ? Action.BLOCK : onSignatureMatch;
        risk = risk == null ? new RiskThresholds(0.3, 0.8) : risk;
        guardThresholds = guardThresholds == null ? new GuardThresholds(0.7, 0.7) : guardThresholds;
        onGuardError = onGuardError == null ? Action.BLOCK : onGuardError;
    }
}
