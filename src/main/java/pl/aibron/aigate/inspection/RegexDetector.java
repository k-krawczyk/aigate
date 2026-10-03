package pl.aibron.aigate.inspection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regex candidate plus an optional checksum or plausibility check. The regex is deliberately loose; the check is
 * what keeps random digit strings from being reported.
 */
public abstract class RegexDetector implements Detector {

    private final String id;
    private final FindingKind kind;
    private final String label;
    private final Pattern pattern;

    protected RegexDetector(String id, FindingKind kind, String label, Pattern pattern) {
        this.id = id;
        this.kind = kind;
        this.label = label;
        this.pattern = pattern;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public FindingKind kind() {
        return kind;
    }

    @Override
    public List<Finding> scan(String text) {
        var findings = new ArrayList<Finding>();
        var matcher = pattern.matcher(text);
        while (matcher.find()) {
            if (isValid(matcher)) {
                int group = sensitiveGroup();
                findings.add(new Finding(id, kind, label, matcher.start(group), matcher.end(group)));
            }
        }
        return findings;
    }

    protected boolean isValid(Matcher match) {
        return true;
    }

    /** Which regex group holds the sensitive part; 0 masks the whole match. */
    protected int sensitiveGroup() {
        return 0;
    }

    protected static String digitsOnly(String text) {
        return text.replaceAll("\\D", "");
    }
}
