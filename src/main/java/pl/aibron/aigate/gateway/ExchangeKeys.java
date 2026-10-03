package pl.aibron.aigate.gateway;

/** Exchange property names shared by the pipeline steps. */
public final class ExchangeKeys {

    public static final String REQUEST_ID = "aigate.requestId";
    public static final String POLICY = "aigate.policy";
    public static final String POLICY_REVISION = "aigate.policyRevision";
    public static final String REQUEST = "aigate.request";
    public static final String IDENTITY = "aigate.identity";
    public static final String CLIENT = "aigate.client";
    public static final String MODEL = "aigate.model";
    public static final String STEP_TIMINGS = "aigate.stepTimings";

    private ExchangeKeys() {
    }
}
