package pl.aibron.aigate.policy;

import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

/**
 * Watches the policy directory rather than the file: editors that save by writing a temp file and renaming it
 * produce a CREATE event on the directory, and a single-file Docker bind mount would keep pointing at the old inode.
 */
@Component
public class PolicyReloadRoute extends RouteBuilder {

    private final PolicyStore store;

    public PolicyReloadRoute(PolicyStore store) {
        this.store = store;
    }

    @Override
    public void configure() {
        fromF("file-watch:%s?events=CREATE,MODIFY&recursive=false&antInclude=%s",
                store.file().getParent().toAbsolutePath(), PolicyStore.FILE_NAME)
                .routeId("policy-reload")
                .process(exchange -> {
                    exchange.getMessage().setBody(store.reload());
                    exchange.getMessage().setHeader("revision", store.active().revision());
                })
                .to("direct:audit-policy-reload");

        // A start from the last known good copy is a security-relevant event: the running policy is not the file.
        from("timer:policy-startup-check?repeatCount=1&delay=1000").routeId("policy-startup-check")
                .filter(exchange -> store.active().fromLastKnownGood())
                .process(exchange -> {
                    exchange.getMessage().setBody(store.lastReload());
                    exchange.getMessage().setHeader("revision", store.active().revision());
                })
                .to("direct:audit-policy-reload");
    }
}
