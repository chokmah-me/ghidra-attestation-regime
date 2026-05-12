// WeightedRegimePropagator.java
// Step 5: Weighted Regime Propagation
//
// Regimes propagate through call edges, but WEIGHTED, not binary:
//   - Call on main execution path vs error/exception path (weight high/low)
//   - Arguments attacker-controlled vs internal-state-derived (weight high/low)
//   - Return value used in safety-critical decision (weight high/low)
//
// Produces a heat map, not binary classification.
//
// Analyst can mark isolation boundaries (MPU regions, separate address spaces)
// where propagation stops. Without these, monolithic firmware images will
// classify almost everything as Regime 3, which is CORRECT and demonstrates
// why hardware isolation is necessary (#24, Limitation 3).

package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Propagates regime classifications through the call graph with weighted
// edges. Produces a heat map showing regime influence per function.
 */
public class WeightedRegimePropagator {

    private final Program program;
    private final TaskMonitor monitor;

    /**
     * Propagation result: final regime with aggregated weight.
     */
    public record PropagationResult(
            AttestationRegime finalRegime,
            double aggregatedWeight,
            List<PropagationEdge> contributingPaths,
            boolean isolationBoundaryHit
    ) {
    }

    public WeightedRegimePropagator(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    /**
     * Step 5: Propagate regimes through the call graph.
     *
     * Iterative fixed-point algorithm:
     // 1. Start with directly-classified functions (weight = 1.0)
     // 2. For each call edge, compute edge weight from path/arg/return analysis
     // 3. Propagate to callers: caller_regime = max over callee_regimes weighted
     // 4. Repeat until convergence or max iterations
     // 5. If propagation would upgrade Regime 1->2 or 2->3, record path
     *
     * @param classifications mutable map of function entry -> classification
     * @param maxIterations   fixed-point iteration limit
     * @return updated classifications after propagation
     */
    public Map<Address, RegimeClassification> propagate(
            Map<Address, RegimeClassification> classifications,
            Set<Address> isolationBoundaries,
            int maxIterations) {

        Map<Address, RegimeClassification> result =
                new HashMap<>(classifications);
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();

        boolean changed = true;
        int iteration = 0;

        while (changed && iteration < maxIterations && !monitor.isCancelled()) {
            changed = false;
            iteration++;

            // For each function that has a classification, propagate to its callers
            for (Map.Entry<Address, RegimeClassification> entry :
                    new HashSet<>(result.entrySet())) {

                Address calleeEntry = entry.getKey();
                RegimeClassification calleeClass = entry.getValue();

                // Skip unclassified
                if (calleeClass.getRegime() == AttestationRegime.UNCLASSIFIED) {
                    continue;
                }

                // Find all callers
                for (Reference ref : refMgr.getReferencesTo(calleeEntry)) {
                    if (monitor.isCancelled()) break;

                    Address callSite = ref.getFromAddress();
                    Function caller = funcMgr.getFunctionContaining(callSite);
                    if (caller == null) continue;

                    Address callerEntry = caller.getEntryPoint();

                    // Check isolation boundary
                    if (isolationBoundaries != null &&
                            isolationBoundaries.contains(callerEntry)) {
                        continue;  // propagation stops at MPU/TrustZone boundary
                    }

                    // Analyze the call edge
                    PropagationEdge edge = analyzeCallEdge(caller, callSite, calleeEntry, calleeClass);

                    // Only propagate if weight exceeds threshold
                    if (edge.getWeight() < 0.3) {
                        continue;  // low-weight path doesn't propagate
                    }

                    RegimeClassification callerClass = result.get(callerEntry);
                    if (callerClass == null) {
                        callerClass = new RegimeClassification(
                                AttestationRegime.REGIME_1, Confidence.LOW);
                        result.put(callerEntry, callerClass);
                    }

                    // Apply weighted dominance
                    AttestationRegime propagated = propagateWeighted(
                            callerClass.getRegime(), calleeClass.getRegime(), edge.getWeight());

                    if (propagated != callerClass.getRegime()) {
                        callerClass.setRegime(propagated);
                        callerClass.addPropagationEdge(edge);
                        changed = true;

                        // Build rationale
                        String rationale = String.format(
                                "Propagated from %s (weight=%.2f): %s -> %s",
                                edge.getCalleeName(), edge.getWeight(),
                                callerClass.getRegime(), propagated);
                        callerClass.setClassificationRationale(rationale);
                    }
                }
            }
        }

        return result;
    }

    /**
     * Analyze a single call edge for path type, argument controllability,
     * and return usage. Returns weighted propagation edge.
     */
    private PropagationEdge analyzeCallEdge(Function caller, Address callSite,
                                           Address calleeEntry,
                                           RegimeClassification calleeClass) {
        Function callee = program.getFunctionManager().getFunctionAt(calleeEntry);
        String calleeName = callee != null ? callee.getName() : "unknown";
        String callerName = caller.getName();

        PropagationEdge.PathType pathType = classifyPathType(caller, callSite);
        PropagationEdge.ArgumentControl argControl = analyzeArgumentControl(calleeClass);
        PropagationEdge.ReturnUsage returnUsage = analyzeReturnUsage(caller, calleeClass);

        return new PropagationEdge(
                caller.getEntryPoint(), calleeEntry,
                callerName, calleeName,
                pathType, argControl, returnUsage
        );
    }

    /**
     * Classify the call site's position in control flow.
     * Heuristic: use reference type to detect computed/indirect calls.
     * Direct calls propagate with higher weight than computed calls.
     */
    private PropagationEdge.PathType classifyPathType(Function caller, Address callSite) {
        // Check if this call site uses a computed target (register, memory dereference)
        // Computed calls indicate indirect dispatch and lower confidence.
        for (Reference ref : program.getReferenceManager().getReferencesFrom(callSite)) {
            if (ref.getReferenceType() == RefType.COMPUTED_CALL ||
                    ref.getReferenceType() == RefType.INDIRECTION) {
                return PropagationEdge.PathType.CALLBACK_PTR;
            }
        }
        // Default to main execution path heuristic
        return PropagationEdge.PathType.MAIN_EXECUTION;
    }

    /**
     * Analyze how much control the caller (and thus potential adversary)
     * has over the arguments passed to the callee.
     * Heuristic: if callee's regime is Regime 3a (external input), then
     * arguments are assumed to be under attacker control. Otherwise assume
     * partial control (internal state + constants).
     */
    private PropagationEdge.ArgumentControl analyzeArgumentControl(RegimeClassification calleeClass) {
        // If callee has Regime 3a input source, arguments are attacker-controlled
        if (calleeClass.getRegime() == AttestationRegime.REGIME_3A) {
            return PropagationEdge.ArgumentControl.ATTACKER_CONTROLLED;
        }
        // If callee is Regime 2 (stochastic), arguments may be partially adversarial
        if (calleeClass.getRegime() == AttestationRegime.REGIME_2) {
            return PropagationEdge.ArgumentControl.SENSOR_DERIVED;
        }
        // Regime 1 or lower: arguments are from internal state or constants
        return PropagationEdge.ArgumentControl.INTERNAL_STATE;
    }

    /**
     * Analyze how the callee's return value is used by the caller.
     * Heuristic: if caller has indirect control flow and callee is Regime 2/3a,
     * return value is critical (drives branch decisions).
     * If callee is Regime 1 (deterministic), return value is less critical.
     */
    private PropagationEdge.ReturnUsage analyzeReturnUsage(Function caller,
                                                           RegimeClassification calleeClass) {
        // If callee is Regime 1, its return is unlikely to be critical
        if (calleeClass.getRegime() == AttestationRegime.REGIME_1) {
            return PropagationEdge.ReturnUsage.CONTROL_FLOW;
        }
        // If callee is Regime 2 or 3a, assume return value is used in control decisions
        return PropagationEdge.ReturnUsage.CONTROL_FLOW;
    }

    /**
     * Weighted regime combination. Higher weight means stronger influence
     * from callee on caller's regime classification.
     *
     * Weight threshold logic:
     *   weight >= 0.7: full propagation (callee regime dominates)
     *   weight 0.3-0.7: partial (upgrade one step max)
     *   weight < 0.3: no propagation
     */
    private AttestationRegime propagateWeighted(AttestationRegime callerRegime,
                                                AttestationRegime calleeRegime,
                                                double weight) {
        if (weight >= 0.7) {
            return AttestationRegime.dominate(callerRegime, calleeRegime);
        }

        if (weight >= 0.3) {
            // Partial propagation: only upgrade caller by at most one regime step
            int callerRank = regimeRank(callerRegime);
            int calleeRank = regimeRank(calleeRegime);
            if (calleeRank > callerRank) {
                return upgradeOneStep(callerRegime);
            }
        }

        return callerRegime;
    }

    private int regimeRank(AttestationRegime r) {
        return switch (r) {
            case UNCLASSIFIED -> 0;
            case REGIME_1 -> 1;
            case REGIME_2 -> 2;
            case PROVENANCE_CHECK -> 3;
            case REGIME_3A -> 4;
        };
    }

    private AttestationRegime upgradeOneStep(AttestationRegime current) {
        return switch (current) {
            case UNCLASSIFIED -> AttestationRegime.REGIME_1;
            case REGIME_1 -> AttestationRegime.REGIME_2;
            case REGIME_2 -> AttestationRegime.REGIME_3A;
            case PROVENANCE_CHECK -> AttestationRegime.REGIME_3A;
            case REGIME_3A -> AttestationRegime.REGIME_3A;
        };
    }
}
