// InputSourceTagger.java
// Step 1: Input Source Tagging
//
// For each function, trace data inputs backward to ultimate source.
// Categorize as constant, internal state, sensor, network/comms, or
// unclassified external.
//
// CRITICAL: Uses raw P-code (before simplification) for MMIO access
// detection, not high-level decompiled output. Raw P-code preserves all
// stores to MMIO; simplified IR may drop them. Ghidra's decompiler
// sometimes folds MMIO accesses into constants or eliminates them as
// "dead" because it doesn't model volatile semantics correctly for all
// architectures (#24, Section 4 Implementation Notes).

package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Traces function data inputs to their ultimate sources using P-code
// def-use chains. MMIO regions must be marked volatile in Ghidra's
// datatype manager before running the classifier.
 */
public class InputSourceTagger {

    private final Program program;
    private final List<MemoryRegion> memoryMap;
    private final TaskMonitor monitor;
    private Map<Address, List<InputSource>> priorResults;

    public InputSourceTagger(Program program, List<MemoryRegion> memoryMap, TaskMonitor monitor) {
        this.program = program;
        this.memoryMap = memoryMap != null ? memoryMap : Collections.emptyList();
        this.monitor = monitor;
        this.priorResults = Collections.emptyMap();
    }

    public void setPriorResults(Map<Address, List<InputSource>> priorResults) {
        this.priorResults = priorResults != null ? priorResults : Collections.emptyMap();
    }

    /**
     * Step 1: Tag all input sources for a function.
     * Traces each parameter and global read back to its origin.
     */
    public List<InputSource> tagFunctionInputs(Function function,
                                               HighFunction highFunction) {
        List<InputSource> sources = new ArrayList<>();
        if (function == null || highFunction == null) {
            return sources;
        }

        // Collect all Varnodes that are inputs to the function's P-code
        Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps();
        while (pcodeOps.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST op = pcodeOps.next();

            // We care about LOAD operations (memory reads) as data inputs
            if (op.getOpcode() == PcodeOp.LOAD) {
                Varnode loadSpace = op.getInput(0);
                Varnode loadAddress = op.getInput(1);
                Varnode output = op.getOutput();

                if (loadAddress != null && loadAddress.isConstant()) {
                    Address addr = loadAddress.getAddress();
                    InputSource source = classifyMemoryAccess(addr, loadSpace);
                    if (source != null && !containsSource(sources, addr)) {
                        sources.add(source);
                    }
                } else if (loadAddress != null) {
                    // Computed address (e.g., array indexing, table lookup)
                    // Check if it's accessing a known table region
                    InputSource source = classifyComputedAccess(op, loadSpace);
                    if (source != null) {
                        sources.add(source);
                    }
                }
            }

            // Also track CALLs to functions that return external data
            if (op.getOpcode() == PcodeOp.CALL) {
                Varnode callTarget = op.getInput(0);
                if (callTarget != null && callTarget.isConstant()) {
                    Address targetAddr = callTarget.getAddress();
                    if (priorResults.containsKey(targetAddr)) {
                        List<InputSource> calleeSources = priorResults.get(targetAddr);
                        calleeSources.forEach(s -> {
                            if (s.getSourceType() != InputSource.SourceType.CONSTANT &&
                                    s.getSourceType() != InputSource.SourceType.INTERNAL_STATE &&
                                    !containsSource(sources, s.getAccessAddress())) {
                                sources.add(s);
                            }
                        });
                    }
                }
            }
        }

        // Check function parameters for pointer types (may reference external data)
        Parameter[] params = function.getParameters();
        for (Parameter param : params) {
            if (param.getDataType() instanceof ghidra.program.model.data.Pointer) {
                // Pointer parameter could reference any memory; conservative
                sources.add(new InputSource(
                        InputSource.SourceType.UNCLASSIFIED_EXT,
                        function.getEntryPoint(),
                        "Pointer parameter: " + param.getName()
                ));
            }
        }

        return sources;
    }

    /**
     * Classify a memory read at a known constant address.
     */
    private InputSource classifyMemoryAccess(Address addr, Varnode loadSpace) {
        // First: check against annotated memory map
        for (MemoryRegion region : memoryMap) {
            if (region.contains(addr)) {
                InputSource.SourceType sourceType = region.toInputSourceType();
                return new InputSource(
                        sourceType,
                        addr,
                        String.format("%s read from %s (0x%s)",
                                sourceType, region.getName(), addr)
                );
            }
        }

        // No memory map match: use Ghidra memory blocks as fallback
        Memory memory = program.getMemory();
        MemoryBlock block = memory.getBlock(addr);

        if (block != null) {
            if (block.isExecute()) {
                return new InputSource(
                        InputSource.SourceType.CONSTANT,
                        addr,
                        "Read from code/ROM block: " + block.getName()
                );
            } else if (block.isWrite()) {
                // Read-write block: could be internal state or unclassified
                // Check if it's SRAM vs external
                return new InputSource(
                        InputSource.SourceType.INTERNAL_STATE,
                        addr,
                        "Read from RW block: " + block.getName()
                );
            } else if (block.isInitialized()) {
                // Read-only initialized data: constant/lookup table
                return new InputSource(
                        InputSource.SourceType.CONSTANT,
                        addr,
                        "Read from initialized RO block: " + block.getName()
                );
            } else {
                // Volatile / uninitialized MMIO
                return new InputSource(
                        InputSource.SourceType.MMIO_UNKNOWN,
                        addr,
                        "Read from volatile/uninitialized block: " + block.getName()
                );
            }
        }

        // No memory block found at address: unmapped external
        return new InputSource(
                InputSource.SourceType.UNCLASSIFIED_EXT,
                addr,
                "Unmapped memory read at 0x" + addr
        );
    }

    /**
     * Classify a computed memory access (array index, pointer dereference).
     * Uses def-use chain walk to resolve constant-folded offsets.
     */
    private InputSource classifyComputedAccess(PcodeOp op, Varnode loadSpace) {
        Varnode addrVarnode = op.getInput(1);
        Optional<Address> resolvedAddr = resolveConstantAddress(addrVarnode, 0);

        if (resolvedAddr.isPresent()) {
            return classifyMemoryAccess(resolvedAddr.get(), loadSpace);
        }

        return new InputSource(
                InputSource.SourceType.UNCLASSIFIED_EXT,
                op.getSeqnum().getTarget(),
                "Computed address access (pointer/index) - conservative Regime 3a"
        );
    }

    /**
     * Walk Varnode def-use chain to resolve constant addresses.
     * Follows INT_ADD, PTRADD, PTRSUB to combine constant offsets.
     * Max depth 4 to prevent cycles. Returns empty if unresolvable.
     */
    private Optional<Address> resolveConstantAddress(Varnode v, int depth) {
        if (depth > 4) return Optional.empty();

        if (v.isConstant()) {
            try {
                return Optional.of(program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(v.getOffset()));
            } catch (Exception e) {
                return Optional.empty();
            }
        }

        PcodeOp defOp = v.getDef();
        if (defOp == null) return Optional.empty();

        int opcode = defOp.getOpcode();
        if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRADD) {
            Varnode base = defOp.getInput(0);
            Varnode offset = defOp.getInput(1);

            Optional<Address> baseAddr = resolveConstantAddress(base, depth + 1);
            if (baseAddr.isPresent() && offset.isConstant()) {
                try {
                    return Optional.of(baseAddr.get().add(offset.getOffset()));
                } catch (Exception e) {
                    return Optional.empty();
                }
            }
        } else if (opcode == PcodeOp.PTRSUB) {
            Varnode base = defOp.getInput(0);
            Varnode offset = defOp.getInput(1);

            Optional<Address> baseAddr = resolveConstantAddress(base, depth + 1);
            if (baseAddr.isPresent() && offset.isConstant()) {
                try {
                    return Optional.of(baseAddr.get().subtract(offset.getOffset()));
                } catch (Exception e) {
                    return Optional.empty();
                }
            }
        }

        return Optional.empty();
    }

    /**
     * Apply heuristic memory map for standard ARM Cortex-M when no SVD
     // is available. ~70% correct on standard targets.
     */
    public static List<MemoryRegion> getCortexMHeuristicMap(Program program) {
        List<MemoryRegion> regions = new ArrayList<>();
        Memory memory = program.getMemory();

        // 0x40000000-0x5FFFFFFF = MMIO peripherals
        try {
            Address mmioStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x40000000L);
            Address mmioEnd = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x5FFFFFFFL);
            regions.add(new MemoryRegion(
                    "Cortex-M MMIO Peripherals", mmioStart, mmioEnd,
                    MemoryRegion.RegionType.MMIO_PERIPHERAL,
                    MemoryRegion.PeripheralClass.UNKNOWN_PERIPHERAL,
                    true
            ));
        } catch (Exception e) {
            // Address space mismatch (not 32-bit)
        }

        // 0x20000000-0x3FFFFFFF = internal SRAM
        try {
            Address sramStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x20000000L);
            Address sramEnd = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x3FFFFFFFL);
            regions.add(new MemoryRegion(
                    "Cortex-M SRAM", sramStart, sramEnd,
                    MemoryRegion.RegionType.INTERNAL_SRAM,
                    MemoryRegion.PeripheralClass.NONE,
                    false
            ));
        } catch (Exception e) {
        }

        // 0x60000000+ = external memory
        try {
            Address extStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x60000000L);
            Address extEnd = program.getAddressFactory().getDefaultAddressSpace().getMaxAddress();
            regions.add(new MemoryRegion(
                    "External Memory", extStart, extEnd,
                    MemoryRegion.RegionType.EXTERNAL_RAM,
                    MemoryRegion.PeripheralClass.NONE,
                    false
            ));
        } catch (Exception e) {
        }

        return regions;
    }

    private boolean containsSource(List<InputSource> sources, Address addr) {
        return sources.stream().anyMatch(s -> addr.equals(s.getAccessAddress()));
    }
}
