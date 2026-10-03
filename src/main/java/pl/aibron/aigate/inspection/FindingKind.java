package pl.aibron.aigate.inspection;

public enum FindingKind {
    PII("sensitive_data", "LLM02"),
    SECRET("secret", "LLM02"),
    SIGNATURE("known_attack", "LLM01"),
    TOOL("tool_misuse", "LLM06"),
    TOOL_ARGUMENT("unsafe_tool_argument", "LLM05"),
    PROMPT_LEAK("system_prompt_leak", "LLM07"),
    UNSAFE_OUTPUT("unsafe_output", "LLM05"),
    TOOL_INJECTION("indirect_prompt_injection", "LLM01");

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
