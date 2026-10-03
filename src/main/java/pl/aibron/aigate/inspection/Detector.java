package pl.aibron.aigate.inspection;

import java.util.List;

public interface Detector {

    String id();

    FindingKind kind();

    List<Finding> scan(String text);
}
