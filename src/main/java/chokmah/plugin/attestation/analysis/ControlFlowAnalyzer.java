// ControlFlowAnalyzer.java
// Step 2: Control Flow Analysis
//
// Per function, extract:
//   - Loop bound status: all statically bounded? (Regime 1 candidate)
//   - Branch predicate sources: any depend on Regime 2/3 source data?
//   - Indirect control flow: computed jumps, function pointers, vtables?
//
// Binary signatures per Section 2:
//   Regime 1: all loops have statically determinable bounds
//             (loop var initialized from constant, incremented by constant,
//             compared to constant), no indirect jumps or calls
//   Regime 3a: data-dependent control flow on adversarial input

package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.ControlFlowProperties;
import chokmah.plugin.attestation.model.MemoryRegion;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Analyzes control flow properties relevant to attestation regime.
 * Operates on decompiled HighFunction for structured analysis and
 * on raw BasicBlockModel for conservative loop detection.
 */
public class ControlFlowAnalyzer {

    private final Program program;
    private final List<MemoryRegion> memoryMap;
    private final TaskMonitor monitor;

    public ControlFlowAnalyzer(Program program, List<MemoryRegion> memoryMap, TaskMonitor monitor) {
        this.program = program;
        this.memoryMap = memoryMap != null ? memoryMap : Collections.emptyList();
        this.monitor = monitor;
    }

    /**
     * Check if a Varnode is derived from external/volatile sources (MMIO, sensors).
     * SSA walk similar to isConstantDerived, but checks LOAD address against memory map.
     */
    private boolean isExternallyDerived(Varnode vn, Set<Varnode> visited, int depth) {
        if (depth > 8 || vn == null || !visited.add(vn)) return false;

        PcodeOp def = vn.getDef();
        if (def == null) return false;

        int opcode = def.getOpcode();

        // If defined by a LOAD, check its address against the memory map
        if (opcode == PcodeOp.LOAD) {
            Varnode addrNode = def.getInput(1);
            if (addrNode != null && addrNode.isConstant()) {
                Address addr = addrNode.getAddress();
                for (MemoryRegion region : memoryMap) {
                    if (region.isVolatile() && region.contains(addr)) {
                        return true;  // Load from volatile/MMIO
                    }
                }
            }
            // Unclassified load address: conservatively assume external
            if (addrNode != null && !addrNode.isConstant()) {
                return true;
            }
        }

        // COPY/CAST/INT_* ops: recurse on inputs
        if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST ||
                (opcode >= PcodeOp.INT_EQUAL && opcode <= PcodeOp.INT_ZEXT)) {
            for (int i = 0; i < def.getNumInputs(); i++) {
                if (isExternallyDerived(def.getInput(i), visited, depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }


    /**
     * Analyze control flow of a function for regime-determining properties.
     */
    public ControlFlowProperties analyze(Function function, HighFunction highFunction) {
        boolean allLoopsBounded = true;
        boolean hasIndirectControlFlow = false;
        boolean hasFloatingPoint = false;
        boolean hasVolatileAccesses = false;
        boolean hasExternallyInfluencedBranches = false;
        int loopCount = 0;
        List<String> unboundedDescriptions = new ArrayList<>();
        List<String> indirectDescriptions = new ArrayList<>();

        if (function == null || highFunction == null) {
            return new ControlFlowProperties(false, false, false, false,
                    0, unboundedDescriptions, indirectDescriptions);
        }

        // Analyze P-code ops for control flow properties
        Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST op = ops.next();

            int opcode = op.getOpcode();

            // Detect indirect control flow (fixed: was CALLIND || CALLIND)
            if (opcode == PcodeOp.BRANCHIND || opcode == PcodeOp.CALLIND) {
                hasIndirectControlFlow = true;
                indirectDescriptions.add(String.format(
                        "Indirect %s at %s",
                        opcode == PcodeOp.BRANCHIND ? "jump" : "call",
                        op.getSeqnum().getTarget()));
            }

            // Detect CBRANCH (conditional branch) for data-dependent control flow
            if (opcode == PcodeOp.CBRANCH) {
                // Trace the condition Varnode back through P-code SSA defs
                // If it depends on external/volatile input, flag as externally-influenced branch
                Varnode condition = op.getInput(0);
                if (isExternallyDerived(condition, new HashSet<>(), 0)) {
                    hasExternallyInfluencedBranches = true;
                    indirectDescriptions.add(String.format(
                            "External-influenced branch at %s", op.getSeqnum().getTarget()));
                }
            }

            // Detect floating point operations
            if (opcode >= PcodeOp.FLOAT_EQUAL && opcode <= PcodeOp.FLOAT_TRUNC) {
                hasFloatingPoint = true;
            }

            // Detect LOAD/STORE to volatile regions
            if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
                Varnode addrNode = op.getInput(opcode == PcodeOp.LOAD ? 1 : 1);
                if (addrNode != null && addrNode.isConstant()) {
                    Address addr = addrNode.getAddress();
                    for (MemoryRegion region : memoryMap) {
                        if (region.isVolatile() && region.contains(addr)) {
                            hasVolatileAccesses = true;
                            break;
                        }
                    }
                }
            }

            // Loop detection via back-edges in control flow graph
            if (isBackEdge(op, highFunction)) {
                loopCount++;
                boolean bounded = analyzeLoopBounds(op, highFunction);
                if (!bounded) {
                    allLoopsBounded = false;
                    unboundedDescriptions.add(String.format(
                            "Unbounded loop at %s", op.getSeqnum().getTarget()));
                }
            }
        }

        // If we found externally-influenced branches, we can't guarantee deterministic control flow
        if (hasExternallyInfluencedBranches) {
            allLoopsBounded = false;
        }

        return new ControlFlowProperties(
                allLoopsBounded,
                hasIndirectControlFlow || hasExternallyInfluencedBranches,
                hasFloatingPoint,
                hasVolatileAccesses,
                loopCount,
                unboundedDescriptions,
                indirectDescriptions
        );
    }

    /**
     * Detect if a P-code op represents a back-edge (loop).
     * A back-edge is a branch whose target address is <= the source address.
     */
    private boolean isBackEdge(PcodeOp op, HighFunction highFunction) {
        int opcode = op.getOpcode();
        if (opcode != PcodeOp.BRANCH && opcode != PcodeOp.CBRANCH) {
            return false;
        }

        int destIdx = (opcode == PcodeOp.CBRANCH) ? 1 : 0;
        Varnode dest = op.getInput(destIdx);
        if (dest == null || !dest.isAddress()) return false;

        Address destAddr = dest.getAddress();
        Address srcAddr = op.getSeqnum().getTarget();
        return destAddr.compareTo(srcAddr) <= 0;
    }

    /**
     * Analyze whether a detected loop has statically determinable bounds.
     *
     * Regime 1 signature: loop var initialized from constant, incremented
     * by constant, compared to constant. Trace the CBRANCH condition back
     * through P-code SSA defs; if all leaves are constants, bounds are static.
     *
     * @return true if loop bounds are statically determinable
     */
    private boolean analyzeLoopBounds(PcodeOp loopOp, HighFunction highFunction) {
        if (loopOp.getOpcode() != PcodeOp.CBRANCH) return false;
        Varnode condition = loopOp.getInput(0);
        return isConstantDerived(condition, new HashSet<>(), 0);
    }

    /**
     * Recursively check if a Varnode is derived entirely from constants.
     * Depth-limited (max 8 levels) to avoid loops in the SSA graph.
     */
    private boolean isConstantDerived(Varnode vn, Set<Varnode> visited, int depth) {
        if (depth > 8 || vn == null || !visited.add(vn)) return false;
        if (vn.isConstant()) return true;
        PcodeOp def = vn.getDef();
        if (def == null) return false;
        for (int i = 0; i < def.getNumInputs(); i++) {
            if (!isConstantDerived(def.getInput(i), visited, depth + 1)) return false;
        }
        return true;
    }

    /**
     * Detect function pointer usage (vtables, callback registration).
     * Scans the function's P-code for patterns like:
     * - Loading address from data section then calling it (vtable call)
     * - Storing function address to a structure field (callback registration)
     */
    public boolean hasFunctionPointerUsage(HighFunction highFunction) {
        if (highFunction == null) return false;

        Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
        Set<Varnode> dataAddresses = new HashSet<>();  // Track addresses loaded from data

        // First pass: identify LOAD ops from data locations (not code)
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opcode = op.getOpcode();

            // Pattern 1: LOAD from data section, then CALLIND on the loaded value
            if (opcode == PcodeOp.LOAD) {
                Varnode addrNode = op.getInput(1);
                Varnode result = op.getOutput();
                if (result != null && addrNode != null && addrNode.isConstant()) {
                    Address loadAddr = addrNode.getAddress();
                    // If not a code address, it's likely data
                    Function loadedFunc = program.getFunctionManager().getFunctionAt(loadAddr);
                    if (loadedFunc == null) {
                        dataAddresses.add(result);
                    }
                }
            }

            // Pattern 2: CALLIND where target is defined by a loaded value
            if (opcode == PcodeOp.CALLIND) {
                Varnode target = op.getInput(0);
                if (target != null) {
                    PcodeOp targetDef = target.getDef();
                    if (targetDef != null) {
                        // Check if target is a LOAD (indirect function pointer)
                        if (targetDef.getOpcode() == PcodeOp.LOAD) {
                            return true;
                        }
                        // Check if target comes from a loaded data value
                        if (dataAddresses.contains(target)) {
                            return true;
                        }
                    }
                }
            }

            // Pattern 3: STORE of a constant code address (callback registration)
            if (opcode == PcodeOp.STORE) {
                Varnode valueNode = op.getInput(1);
                if (valueNode != null && valueNode.isConstant()) {
                    Address storedAddr = valueNode.getAddress();
                    Function storedFunc = program.getFunctionManager().getFunctionAt(storedAddr);
                    if (storedFunc != null) {
                        // Storing a function address indicates callback/vtable pattern
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
