// PropagationEdge.java
// Weighted call-graph edge for regime propagation (Step 5)

package chokmah.plugin.attestation.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;

/**
 * A single propagation step through the call graph.
 * Weighted, not binary: call on main path vs error path, attacker-controlled
 * args vs internal state, safety-critical return vs diagnostic.
 */
public class PropagationEdge {

    public enum PathType {
        MAIN_EXECUTION,      // call on primary control-flow path -> high weight
        ERROR_HANDLER,       // call in exception/dead-code path -> low weight
        CALLBACK_PTR,        // indirect call via function pointer -> medium weight
        INTERRUPT_HANDLER    // ISR entry point -> high weight (safety-critical)
    }

    public enum ArgumentControl {
        INTERNAL_STATE,      // args derived from internal globals -> low weight
        SENSOR_DERIVED,      // args from sensor input -> medium weight
        ATTACKER_CONTROLLED, // args from network/untrusted source -> high weight
        CONSTANT             // literal args -> negligible weight
    }

    public enum ReturnUsage {
        SAFETY_CRITICAL,     // drives actuator, safety interlock, watchdog -> high weight
        CONTROL_FLOW,        // determines branching -> medium weight
        DIAGNOSTIC_ONLY,     // logging, status LED, non-critical -> low weight
        UNUSED               // return discarded -> negligible weight
    }

    private final Address callerEntry;
    private final Address calleeEntry;
    private final String callerName;
    private final String calleeName;
    private final PathType pathType;
    private final ArgumentControl argumentControl;
    private final ReturnUsage returnUsage;
    private final double weight;

    public PropagationEdge(Address callerEntry, Address calleeEntry,
                           String callerName, String calleeName,
                           PathType pathType, ArgumentControl argumentControl,
                           ReturnUsage returnUsage) {
        this.callerEntry = callerEntry;
        this.calleeEntry = calleeEntry;
        this.callerName = callerName;
        this.calleeName = calleeName;
        this.pathType = pathType;
        this.argumentControl = argumentControl;
        this.returnUsage = returnUsage;
        this.weight = computeWeight(pathType, argumentControl, returnUsage);
    }

    /**
     * Weighted regime propagation formula.
     * Combines path criticality, argument controllability, and return usage.
     * Range: [0.0, 1.0].
     */
    private double computeWeight(PathType pt, ArgumentControl ac, ReturnUsage ru) {
        double w = 0.0;
        w += switch (pt) {
            case MAIN_EXECUTION -> 0.4;
            case INTERRUPT_HANDLER -> 0.4;
            case CALLBACK_PTR -> 0.25;
            case ERROR_HANDLER -> 0.1;
        };
        w += switch (ac) {
            case ATTACKER_CONTROLLED -> 0.35;
            case SENSOR_DERIVED -> 0.2;
            case INTERNAL_STATE -> 0.1;
            case CONSTANT -> 0.0;
        };
        w += switch (ru) {
            case SAFETY_CRITICAL -> 0.25;
            case CONTROL_FLOW -> 0.15;
            case DIAGNOSTIC_ONLY -> 0.05;
            case UNUSED -> 0.0;
        };
        return Math.min(w, 1.0);
    }

    public Address getCallerEntry() {
        return callerEntry;
    }

    public Address getCalleeEntry() {
        return calleeEntry;
    }

    public String getCallerName() {
        return callerName;
    }

    public String getCalleeName() {
        return calleeName;
    }

    public PathType getPathType() {
        return pathType;
    }

    public ArgumentControl getArgumentControl() {
        return argumentControl;
    }

    public ReturnUsage getReturnUsage() {
        return returnUsage;
    }

    public double getWeight() {
        return weight;
    }
}
