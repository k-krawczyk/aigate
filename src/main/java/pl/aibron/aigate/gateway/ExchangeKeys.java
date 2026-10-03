package pl.aibron.aigate.gateway;

/** Exchange property names shared by the pipeline steps. */
public final class ExchangeKeys {

    public static final String REQUEST_ID = "aigate.requestId";
    public static final String POLICY = "aigate.policy";
    public static final String POLICY_REVISION = "aigate.policyRevision";
    public static final String REQUEST = "aigate.request";
    public static final String IDENTITY = "aigate.identity";
    public static final String CLIENT = "aigate.client";
    public static final String PROFILE = "aigate.profile";
    public static final String PROFILE_NAME = "aigate.profileName";
    public static final String MODEL = "aigate.model";
    public static final String STEP_TIMINGS = "aigate.stepTimings";
    public static final String STARTED_NANOS = "aigate.startedNanos";
    public static final String FINDINGS = "aigate.findings";
    public static final String EXCERPT = "aigate.excerpt";
    public static final String DECISION = "aigate.decision";
    public static final String CATEGORY = "aigate.category";
    public static final String OWASP = "aigate.owasp";
    public static final String DIRECTION = "aigate.direction";
    public static final String CANARY = "aigate.canary";
    public static final String STREAM = "aigate.stream";
    public static final String USAGE_TOKENS = "aigate.usageTokens";
    public static final String COST_USD = "aigate.costUsd";
    public static final String RISK_SCORE = "aigate.riskScore";
    public static final String SEMANTIC_NOTE = "aigate.semanticNote";
    public static final String SEMANTIC_RULE = "aigate.semanticRule";
    public static final String AUTH_RULE = "aigate.authRule";
    public static final String AUTH_DETAIL = "aigate.authDetail";

    private ExchangeKeys() {
    }
}
