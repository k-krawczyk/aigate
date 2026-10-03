package pl.aibron.aigate.dashboard;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import pl.aibron.aigate.budget.BudgetLedger;
import pl.aibron.aigate.policy.PolicyStore;
import pl.aibron.aigate.signatures.SignatureFeed;

@Controller
public class DashboardController {

    /** Budget consumption of one client in the current window, as fractions for the meter bars. */
    public record BudgetMeter(String clientId, String profile, String window, long tokensUsed, Long maxTokens,
                              double costUsed, Double maxCost, double secondsUsed, Long maxSeconds, int requests) {

        public double tokenShare() {
            return share(tokensUsed, maxTokens == null ? null : maxTokens.doubleValue());
        }

        public double costShare() {
            return share(costUsed, maxCost);
        }

        public double timeShare() {
            return share(secondsUsed, maxSeconds == null ? null : maxSeconds.doubleValue());
        }

        private static double share(double used, Double max) {
            return max == null || max == 0 ? (used > 0 ? 1 : 0) : Math.min(1, used / max);
        }
    }

    private static final Duration REPORT_WINDOW = Duration.ofHours(24);
    private static final Duration TIMELINE_WINDOW = Duration.ofHours(2);
    private static final Duration BUCKET = Duration.ofMinutes(5);

    private final AuditQueries audit;
    private final PolicyStore policyStore;
    private final SignatureFeed signatureFeed;
    private final BudgetLedger ledger;

    public DashboardController(AuditQueries audit, PolicyStore policyStore, SignatureFeed signatureFeed,
                               BudgetLedger ledger) {
        this.audit = audit;
        this.policyStore = policyStore;
        this.signatureFeed = signatureFeed;
        this.ledger = ledger;
    }

    @GetMapping({"/", "/dashboard", "/dashboard/security"})
    public String security(Model model, @RequestParam(required = false) String decision) {
        fillSecurity(model, decision);
        return "security";
    }

    @GetMapping("/dashboard/security/live")
    public String securityLive(Model model, @RequestParam(required = false) String decision) {
        fillSecurity(model, decision);
        return "security :: live";
    }

    @GetMapping("/dashboard/management")
    public String management(Model model) {
        fillManagement(model);
        return "management";
    }

    @GetMapping("/dashboard/management/live")
    public String managementLive(Model model) {
        fillManagement(model);
        return "management :: live";
    }

    /** Chart data; the page polls it and updates charts in place instead of re-rendering them. */
    @GetMapping("/dashboard/api/timeline")
    @ResponseBody
    public List<AuditQueries.Bucket> timeline() {
        return audit.timeline(Instant.now().minus(TIMELINE_WINDOW), BUCKET);
    }

    private void fillSecurity(Model model, String decision) {
        var since = Instant.now().minus(REPORT_WINDOW);
        model.addAttribute("view", "security");
        model.addAttribute("summary", audit.summarySince(since));
        model.addAttribute("categories", audit.categories(since));
        model.addAttribute("rules", audit.topRules(since, 8));
        model.addAttribute("latency", audit.stepLatency(500));
        model.addAttribute("events", audit.recent(40, decision == null || decision.isBlank() ? null : decision));
        model.addAttribute("decisionFilter", decision);
        model.addAttribute("controlEvents", audit.controlEvents(8));
        model.addAttribute("policy", policyStore.active());
        model.addAttribute("lastReload", policyStore.lastReload());
        model.addAttribute("feed", signatureFeed.status());
    }

    private void fillManagement(Model model) {
        var since = Instant.now().minus(REPORT_WINDOW);
        var policy = policyStore.current();
        model.addAttribute("view", "management");
        model.addAttribute("summary", audit.summarySince(since));
        model.addAttribute("clients", audit.clients(since));
        model.addAttribute("models", audit.models(since));
        model.addAttribute("policy", policyStore.active());
        model.addAttribute("lastReload", policyStore.lastReload());
        model.addAttribute("budgets", policy.clients().stream().map(client -> {
            var budgets = policy.budgetsOf(client);
            BudgetLedger.Usage used;
            try {
                used = ledger.usage(client.id(), budgets.windowDuration());
            } catch (pl.aibron.aigate.budget.BudgetStoreUnavailableException e) {
                used = BudgetLedger.Usage.NONE;
            }
            return new BudgetMeter(client.id(), client.profile(), budgets.window(), used.tokens(),
                    budgets.maxTokens(), used.costUsd(), budgets.maxCostUsd(), used.modelSeconds(),
                    budgets.maxModelSeconds(), used.requests());
        }).toList());
        model.addAttribute("modelKinds", Map.copyOf(policy.models().stream()
                .collect(java.util.stream.Collectors.toMap(m -> m.name(), m -> m.kind().name().toLowerCase()))));
    }
}
