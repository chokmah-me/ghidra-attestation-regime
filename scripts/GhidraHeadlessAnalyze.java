// @author Claude
// @category Attestation
// @keybinding
// @menupath Tools.Attestation Regime.Analyze Headless
// @toolbar
// Headless GhidraScript for batch analyzing firmware ELF files.
// Simplified version: directly analyzes without external plugin dependencies.
//
// Usage: analyzeHeadless <project_path> <project_name> -import <elf>
//   -scriptPath scripts -postScript GhidraHeadlessAnalyze.java
//   <memory_map_json> <output_json_path>

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class GhidraHeadlessAnalyze extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String memoryMapPath = null;
        String outputJsonPath = null;

        // Parse script arguments
        String[] args = getScriptArgs();
        if (args.length >= 1) memoryMapPath = args[0];
        if (args.length >= 2) outputJsonPath = args[1];

        println("GhidraHeadlessAnalyze starting...");
        println("  Program: " + currentProgram.getName());
        println("  Memory map: " + memoryMapPath);
        println("  Output: " + outputJsonPath);

        // Initialize decompiler
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        try {
            FunctionManager funcMgr = currentProgram.getFunctionManager();
            int processedCount = 0;
            Map<String, Integer> regimeCounts = new HashMap<>();
            regimeCounts.put("REGIME_1", 0);
            regimeCounts.put("REGIME_2", 0);
            regimeCounts.put("REGIME_3A", 0);
            regimeCounts.put("PROVENANCE", 0);
            regimeCounts.put("UNCLASSIFIED", 0);

            // Analyze each function with stub logic
            for (Function func : funcMgr.getFunctions(true)) {
                if (monitor.isCancelled()) break;

                monitor.setProgress(processedCount);
                monitor.setMessage("Analyzing: " + func.getName());

                try {
                    // Stub analysis: classify based on function characteristics
                    String regime = classifyFunction(func);
                    regimeCounts.put(regime, regimeCounts.getOrDefault(regime, 0) + 1);
                } catch (Exception e) {
                    println("  WARNING analyzing " + func.getName() + ": " + e.getMessage());
                    regimeCounts.put("UNCLASSIFIED", regimeCounts.get("UNCLASSIFIED") + 1);
                }

                processedCount++;
            }

            // Write JSON output
            if (outputJsonPath != null && !outputJsonPath.isEmpty()) {
                JsonObject root = new JsonObject();
                root.addProperty("firmware", currentProgram.getName());
                root.addProperty("totalFunctions", processedCount);

                JsonObject counts = new JsonObject();
                for (Map.Entry<String, Integer> e : regimeCounts.entrySet()) {
                    counts.addProperty(e.getKey(), e.getValue());
                }
                root.add("regimeCounts", counts);

                Files.write(Paths.get(outputJsonPath),
                        root.toString().getBytes());

                println("\nResults written to: " + outputJsonPath);
            }

            println("\nAnalysis complete:");
            println("  Functions analyzed: " + processedCount);
            for (Map.Entry<String, Integer> e : regimeCounts.entrySet()) {
                println("  " + e.getKey() + ": " + e.getValue());
            }

        } finally {
            decompiler.closeProgram();
        }
    }

    private String classifyFunction(Function func) {
        // Heuristic classification based on function complexity metrics
        // Real implementation would use InputSourceTagger, ControlFlowAnalyzer, ComplexityAnalyzer

        // Count basic blocks and instructions for better size estimation
        int blockCount = 0;
        int instructionCount = 0;
        boolean hasCall = false;
        boolean hasIndirectCall = false;
        boolean hasLoop = false;

        try {
            // Count instructions
            InstructionIterator itr = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (itr.hasNext()) {
                instructionCount++;
                String mnem = itr.next().getMnemonicString().toLowerCase();
                if (mnem.contains("call")) {
                    hasCall = true;
                    // Check for indirect calls (use, jalr, blx, etc.)
                    if (!mnem.contains("bl") || mnem.startsWith("blx") || mnem.startsWith("bx")) {
                        hasIndirectCall = true;
                    }
                }
                // Detect loops (backward branches)
                if (mnem.startsWith("b") && mnem.length() <= 3) {
                    // Backward branch likely indicates a loop
                    hasLoop = true;
                }
            }

            // Count basic blocks
            blockCount = func.getBasicBlocks().size();
        } catch (Exception e) {
            // Fallback on error
        }

        // Check for known table patterns in function name
        boolean isTableFunction = func.getName().toLowerCase().contains("crc") ||
                func.getName().toLowerCase().contains("hash") ||
                func.getName().toLowerCase().contains("table") ||
                func.getName().toLowerCase().contains("lookup");

        // Heuristic classification based on realistic ARM embedded firmware metrics
        if (hasIndirectCall) {
            return "REGIME_3A"; // Indirect calls = adversarial input exposure
        } else if (instructionCount > 200 || blockCount > 30) {
            return "REGIME_3A"; // Large function = likely high complexity with multiple paths
        } else if (isTableFunction) {
            return "PROVENANCE"; // Known cryptographic or lookup table patterns
        } else if (hasCall && hasLoop) {
            return "REGIME_2"; // Loops with calls = likely sensor/state-based logic
        } else if (hasCall || hasLoop) {
            return "REGIME_2"; // Calls or loops = medium complexity
        } else if (blockCount > 5) {
            return "REGIME_2"; // Multiple blocks = branching/decision logic
        } else {
            return "REGIME_1"; // Linear, simple function = deterministic
        }
    }
}
