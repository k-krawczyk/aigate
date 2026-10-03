package pl.aibron.aigate.inspection;

public enum FindingKind {
    PII("sensitive_data", "LLM02"),
    SECRET("secret", "LLM02"),
    SIGNATURE("known_attack", "LLM01"),
    TOOL("tool_misuse", "LLM06");

    private final String category;
    private final String owasp;

    FindingKind(String category, String owasp) {
        this.category = category;
        this.owasp = owasp;
    }

    public String category() {
        return category;
    }

    public String owasp() {
        return owasp;
    }
}
