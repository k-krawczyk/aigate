package pl.aibron.aigate.dashboard;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Audit export for security teams: JSON Lines for SIEM ingestion, CSV for spreadsheets. */
@RestController
public class AuditExportController {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final AuditQueries audit;

    public AuditExportController(AuditQueries audit) {
        this.audit = audit;
    }

    @GetMapping("/audit/export")
    public ResponseEntity<String> export(@RequestParam(defaultValue = "jsonl") String format,
                                         @RequestParam(defaultValue = "24") int hours) {
        var rows = audit.allSince(Instant.now().minus(Duration.ofHours(hours)));
        boolean csv = "csv".equalsIgnoreCase(format);
        var body = csv ? toCsv(rows) : rows.stream().map(AuditExportController::toJson).collect(Collectors.joining("\n"));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"aigate-audit." + (csv ? "csv" : "jsonl") + "\"")
                .contentType(csv ? MediaType.parseMediaType("text/csv") : MediaType.parseMediaType("application/x-ndjson"))
                .body(body);
    }

    private static String toJson(Map<String, Object> row) {
        var lower = new LinkedHashMap<String, Object>();
        row.forEach((k, v) -> lower.put(k.toLowerCase(), v instanceof Timestamp t ? t.toInstant().toString() : v));
        try {
            return JSON.writeValueAsString(lower);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String toCsv(List<Map<String, Object>> rows) {
        if (rows.isEmpty()) {
            return "";
        }
        var header = String.join(",", rows.getFirst().keySet().stream().map(String::toLowerCase).toList());
        var lines = rows.stream().map(r -> r.values().stream().map(AuditExportController::csvCell)
                .collect(Collectors.joining(",")));
        return header + "\n" + lines.collect(Collectors.joining("\n")) + "\n";
    }

    private static String csvCell(Object value) {
        if (value == null) {
            return "";
        }
        var text = value instanceof Timestamp t ? t.toInstant().toString() : value.toString();
        // Leading =,+,-,@ would be evaluated as formulas when a security analyst opens the file in a spreadsheet.
        if (!text.isEmpty() && "=+-@".indexOf(text.charAt(0)) >= 0) {
            text = "'" + text;
        }
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }
}
