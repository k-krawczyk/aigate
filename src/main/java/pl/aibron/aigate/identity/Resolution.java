package pl.aibron.aigate.identity;

/**
 * Outcome of one resolver for one Authorization header.
 *
 * <ul>
 *   <li>{@code accepted}: the caller is known.</li>
 *   <li>{@code rejected}: the header was for this resolver and it said no. {@code rule} goes to the audit trail;
 *       {@code knownCaller} is set only when the credential itself was verified (a valid IdP token for an agent
 *       that is not onboarded), never from claims of an unverified token.</li>
 *   <li>{@code notApplicable}: the header is some other kind of credential.</li>
 * </ul>
 * The client always gets the same generic 401; the detail is for the SOC.
 */
public record Resolution(CallerIdentity identity, String rule, String detail, CallerIdentity knownCaller) {

    private static final Resolution NOT_APPLICABLE = new Resolution(null, null, null, null);

    public static Resolution accepted(CallerIdentity identity) {
        return new Resolution(identity, null, null, null);
    }

    public static Resolution rejected(String rule, String detail) {
        return new Resolution(null, rule, detail, null);
    }

    public static Resolution rejectedVerified(String rule, String detail, CallerIdentity knownCaller) {
        return new Resolution(null, rule, detail, knownCaller);
    }

    public static Resolution notApplicable() {
        return NOT_APPLICABLE;
    }

    public boolean isAccepted() {
        return identity != null;
    }

    public boolean isRejected() {
        return rule != null;
    }
}
