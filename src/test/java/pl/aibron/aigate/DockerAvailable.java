package pl.aibron.aigate;

import org.testcontainers.DockerClientFactory;

/** Condition for tests that start containers: they are skipped, not failed, on machines without Docker. */
public final class DockerAvailable {

    private DockerAvailable() {
    }

    public static boolean dockerAvailable() {
        try {
            return DockerClientFactory.instance().isDockerAvailable();
        } catch (RuntimeException e) {
            return false;
        }
    }
}
