package pl.aibron.aigate.policy;

import java.util.List;

public class InvalidPolicyException extends Exception {

    private final List<String> errors;

    public InvalidPolicyException(List<String> errors) {
        super(String.join("; ", errors));
        this.errors = List.copyOf(errors);
    }

    public List<String> errors() {
        return errors;
    }
}
