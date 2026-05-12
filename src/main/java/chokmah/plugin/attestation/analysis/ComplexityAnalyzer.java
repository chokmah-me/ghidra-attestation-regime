// ComplexityAnalyzer.java
// Step 3: Complexity Assessment
//
// Compute per function:
//   - Cyclomatic complexity from decompiled CFG
//   - Lookup table size (contiguous read-only arrays referenced)
//   - Code size in P-code operations
//
// Flag functions with tables >= 256 entries + data-dependent branching
// on table output as provenance-check candidates (Regime 3b flag).
//
// PRF-embeddability detection from static analysis produces too many false
// positives. CRC tables and backdoor triggers look identical. The plugin
// flags candidates; the analyst decides (#24, Section 2, Limitation 1).

package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.*;
import chokmah.plugin.attestation.model.ComplexityMetrics;
import chokmah.plugin.attestation.model.TableCandidate;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Assesses complexity metrics and flags provenance-check candidates.
 */
public class ComplexityAnalyzer {

    private final Program program;
    private final TaskMonitor monitor;


    public ComplexityAnalyzer(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    /**
     * Step 3: Analyze complexity metrics and flag provenance candidates.
     */
    public ComplexityMetrics analyze(Function function, HighFunction highFunction) {
        int cyclomatic = computeCyclomaticComplexity(function, highFunction);
        List<TableCandidate> tables = findLookupTables(function, highFunction);
        int pcodeOps = countPcodeOperations(highFunction);

        int totalTableEntries = tables.stream()
                .mapToInt(TableCandidate::entryCount)
                .sum();

        boolean isProvCandidate = false;
        double provScore = 0.0;

        // Flag: tables >= 256 entries + data-dependent branching on table output
        for (TableCandidate tc : tables) {
            if (tc.isUnexplained() && tc.entryCount >= 256) {
                // TODO: verify data-dependent branching on this table's output
                // requires cross-referencing with ControlFlowAnalyzer branch predicates
                isProvCandidate = true;
                provScore += tc.entryCount / 256.0;  // scoring heuristic
            }
        }

        return new ComplexityMetrics(
                cyclomatic,
                totalTableEntries,
                pcodeOps,
                isProvCandidate,
                Math.min(provScore, 10.0),
                tables
        );
    }

    /**
     * Cyclomatic complexity from decompiled control flow graph.
     * M = E - N + 2P, where E = edges, N = nodes, P = connected components.
     */
    private int computeCyclomaticComplexity(Function function, HighFunction highFunction) {
        if (highFunction == null) {
            // Fallback: count basic blocks from raw disassembly
            try {
                CodeBlockModel blockModel = new BasicBlockModel(program);
                CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(
                        function.getBody(), monitor);
                int blockCount = 0;
                int edgeCount = 0;
                while (blocks.hasNext()) {
                    CodeBlock block = blocks.next();
                    blockCount++;
                    CodeBlockReferenceIterator refs = blockModel.getDestinations(block, monitor);
                    while (refs.hasNext()) {
                        refs.next();
                        edgeCount++;
                    }
                }
                return edgeCount - blockCount + 2;
            } catch (Exception e) {
                return -1;
            }
        }

        // Use decompiled CFG
        // TODO: iterate HighFunction basic blocks and count edges/nodes
        return 1; // placeholder
    }

    /**
     * Find contiguous read-only arrays referenced by the function.
     * These are candidate lookup tables for provenance checking.
     */
    private List<TableCandidate> findLookupTables(Function function, HighFunction highFunction) {
        List<TableCandidate> candidates = new ArrayList<>();
        if (highFunction == null) {
            return candidates;
        }

        // Scan P-code for LOAD operations with constant addresses in read-only memory
        Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
        Set<Address> checkedAddresses = new HashSet<>();

        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST op = ops.next();

            if (op.getOpcode() == PcodeOp.LOAD) {
                Varnode addrNode = op.getInput(1);
                if (addrNode != null && addrNode.isConstant()) {
                    Address tableAddr = addrNode.getAddress();
                    if (checkedAddresses.contains(tableAddr)) continue;
                    checkedAddresses.add(tableAddr);

                    TableCandidate tc = analyzeTableAtAddress(tableAddr);
                    if (tc != null) {
                        candidates.add(tc);
                    }
                }
            }
        }

        // Also check direct data references from disassembly
        ReferenceManager refMgr = program.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(function.getEntryPoint());
        for (Reference ref : refs) {
            if (ref.getReferenceType().isData()) {
                Address dataAddr = ref.getToAddress();
                if (checkedAddresses.contains(dataAddr)) continue;
                checkedAddresses.add(dataAddr);

                TableCandidate tc = analyzeTableAtAddress(dataAddr);
                if (tc != null) {
                    candidates.add(tc);
                }
            }
        }

        return candidates;
    }

    /**
     * Analyze a memory location to determine if it contains a lookup table.
     */
    private TableCandidate analyzeTableAtAddress(Address addr) {
        Memory memory = program.getMemory();
        MemoryBlock block = memory.getBlock(addr);

        // Must be in read-only initialized memory to be a constant table
        if (block == null || block.isWrite() || !block.isInitialized()) {
            return null;
        }

        // Try to determine array bounds from data type at this address
        Data data = program.getListing().getDataContaining(addr);
        if (data == null || !data.getDataType().isEquivalent(new ArrayDataType())) {
            // No typed array; use heuristic byte scan
            return heuristicTableScan(addr, block);
        }

        // Has typed array data
        DataType dt = data.getDataType();
        int elementSize = dt.getLength();
        if (elementSize <= 0) elementSize = 1;

        int totalBytes = dt.getLength();
        int entries = totalBytes / elementSize;

        // Only flag tables >= 256 entries or with suspicious size
        if (entries < 16 && totalBytes < 64) {
            return null;  // too small to be relevant
        }

        byte[] tableData = new byte[Math.min(totalBytes, 4096)];
        try {
            memory.getBytes(addr, tableData);
        } catch (MemoryAccessException e) {
            return null;
        }

        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(tableData, elementSize);
        boolean unexplained = (match == null && KnownConstantTables.isTableSizeSuspicious(totalBytes, elementSize));

        return new TableCandidate(addr.getOffset(), totalBytes, elementSize, entries, match, unexplained);
    }

    /**
     * Heuristic scan for untyped constant tables in read-only memory.
     * Looks for contiguous non-zero data of significant size.
     */
    private TableCandidate heuristicTableScan(Address addr, MemoryBlock block) {
        // TODO: implement heuristic table detection
        // Scan forward from addr looking for:
        // 1. Contiguous non-zero bytes
        // 2. Pattern repetition suggesting table structure
        // 3. Size threshold (>= 256 bytes for heuristic)
        return null;
    }

    private int countPcodeOperations(HighFunction highFunction) {
        if (highFunction == null) return 0;
        int count = 0;
        Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
        while (ops.hasNext()) {
            ops.next();
            count++;
        }
        return count;
    }
}
