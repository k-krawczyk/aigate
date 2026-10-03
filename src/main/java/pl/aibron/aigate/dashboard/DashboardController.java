package pl.aibron.aigate.dashboard;

import java.time.Duration;
import java.time.Instant;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import pl.aibron.aigate.policy.PolicyStore;

@Controller
public class DashboardController {

    private final AuditQueries audit;
    private final PolicyStore policyStore;

    public DashboardController(AuditQueries audit, PolicyStore policyStore) {
        this.audit = audit;
        this.policyStore = policyStore;
    }

    @GetMapping({"/", "/dashboard"})
    public String dashboard(Model model) {
        fill(model);
        return "dashboard";
    }

    /** Polled by htmx; returns only the live part of the page. */
    @GetMapping("/dashboard/live")
    public String live(Model model) {
        fill(model);
        return "dashboard :: live";
    }

    private void fill(Model model) {
        model.addAttribute("summary", audit.summarySince(Instant.now().minus(Duration.ofHours(1))));
        model.addAttribute("events", audit.recent(50));
        model.addAttribute("policy", policyStore.active());
        model.addAttribute("lastReload", policyStore.lastReload());
    }
}
