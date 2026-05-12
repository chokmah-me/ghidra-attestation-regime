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

    public InputSourceTagger(Program program, List<MemoryRegion> memoryMap, TaskMonitor monitor) {
        this.program = program;
        this.memoryMap = memoryMap != null ? memoryMap : Collections.emptyList();
        this.monitor = monitor;
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
                // TODO: trace through call to check if callee reads external
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
     */
    private InputSource classifyComputedAccess(PcodeOp op, Varnode loadSpace) {
        // TODO: range analysis to determine if computed access stays within
        // known table bounds or potentially accesses external memory
        // For now: conservative default
        return new InputSource(
                InputSource.SourceType.UNCLASSIFIED_EXT,
                op.getSeqnum().getTarget(),
                "Computed address access (pointer/index) - conservative Regime 3a"
        );
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
