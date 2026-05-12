package chokmah.plugin.attestation.model;

import java.util.List;

/**
 * Control flow properties extracted from a function analysis.
 * These are pure Java data structures with no Ghidra dependencies.
 */
public record ControlFlowProperties(
        boolean allLoopsBounded,
        boolean hasIndirectControlFlow,
        boolean hasFloatingPoint,
        boolean hasVolatileAccesses,
        int loopCount,
        List<String> unboundedLoopDescriptions,
        List<String> indirectFlowDescriptions
) {
}
