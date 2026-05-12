package chokmah.plugin.attestation.model;

import java.util.List;

/**
 * Complexity metrics and provenance check assessment.
 * Pure Java with no Ghidra dependencies.
 */
public record ComplexityMetrics(
        int cyclomaticComplexity,
        int lookupTableEntries,
        int pcodeOpCount,
        boolean isProvenanceCheckCandidate,
        double provenanceCheckScore,
        List<TableCandidate> tableCandidates
) {
}
