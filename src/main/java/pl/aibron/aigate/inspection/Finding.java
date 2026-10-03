package pl.aibron.aigate.inspection;

/**
 * One match in one piece of text. Holds offsets and a label, never the matched value, so findings can be logged
 * and audited without leaking what they found. Category and OWASP id default to the kind's; feed signatures carry
 * their own.
 */
public record Finding(String detector, FindingKind kind, String label, int start, int end, String category,
                      String owasp) {

    public Finding(String detector, FindingKind kind, String label, int start, int end) {
        this(detector, kind, label, start, end, kind.category(), kind.owasp());
    }

    public boolean overlaps(Finding other) {
        return start < other.end && other.start < end;
    }
}
