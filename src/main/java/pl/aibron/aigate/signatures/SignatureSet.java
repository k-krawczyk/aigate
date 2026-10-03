package pl.aibron.aigate.signatures;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

/** A parsed, validated and compiled feed. Swapped as a whole, so a request never sees half of an update. */
public record SignatureSet(String version, String source, String origin, Instant loadedAt, List<Compiled> signatures) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Signature(String id, String name, String category, String owasp, String severity, String pattern,
                            String reference) { }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Feed(String version, String source, List<Signature> signatures) { }

    public record Compiled(Signature signature, Pattern pattern) { }

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Rejects the whole feed on any invalid entry. A feed is external input; applying the valid half of a broken
     * one would silently drop protections.
     */
    public static SignatureSet parse(String json, String origin) {
        Feed feed;
        try {
            feed = JSON.readValue(json, Feed.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("feed is not valid JSON: " + e.getMessage());
        }
        if (feed.signatures() == null || feed.signatures().isEmpty()) {
            throw new IllegalArgumentException("feed has no signatures");
        }
        var ids = new HashSet<String>();
        var compiled = new ArrayList<Compiled>();
        for (var s : feed.signatures()) {
            if (s.id() == null || s.pattern() == null || s.category() == null) {
                throw new IllegalArgumentException("signature without id, category or pattern");
            }
            if (!ids.add(s.id())) {
                throw new IllegalArgumentException("duplicate signature id " + s.id());
            }
            try {
                compiled.add(new Compiled(s, Pattern.compile(s.pattern())));
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException("signature " + s.id() + " has an invalid pattern");
            }
        }
        return new SignatureSet(feed.version(), feed.source(), origin, Instant.now(), List.copyOf(compiled));
    }
}
