package pl.aibron.aigate.gateway;

/**
 * Stops the pipeline with a client-facing error. The message must never contain the sensitive content that caused it.
 */
public class GatewayRejection extends RuntimeException {

    private final int status;
    private final String code;
    private final String category;
    private final String owasp;

    public GatewayRejection(int status, String code, String category, String message) {
        this(status, code, category, null, message);
    }

    public GatewayRejection(int status, String code, String category, String owasp, String message) {
        super(message, null, false, false);
        this.status = status;
        this.code = code;
        this.category = category;
        this.owasp = owasp;
    }

    public String owasp() {
        return owasp;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public String category() {
        return category;
    }

    public String openAiType() {
        return switch (status) {
            case 400 -> "invalid_request_error";
            case 401 -> "authentication_error";
            case 403 -> "permission_error";
            case 429 -> "rate_limit_error";
            default -> "api_error";
        };
    }
}
