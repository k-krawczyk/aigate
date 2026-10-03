package pl.aibron.aigate.inspection;

/**
 * One match in one piece of text. Holds offsets and a label, never the matched value, so findings can be logged
 * and audited without leaking what they found.
 */
public record Finding(String detector, FindingKind kind, String label, int start, int end) {

    public boolean overlaps(Finding other) {
        return start < other.end && other.start < end;
    }
}
