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
    }
}
