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
        // Stub: classify based on simple heuristics
        // Real implementation would use InputSourceTagger, ControlFlowAnalyzer, etc.

        long blockCount = func.getBody().getNumAddresses();
        boolean hasCall = false;

        // Check for CALL instructions
        try {
            InstructionIterator itr = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (itr.hasNext()) {
                if (itr.next().getMnemonicString().toLowerCase().contains("call")) {
                    hasCall = true;
                    break;
                }
            }
        } catch (Exception e) {
            // Ignore
        }

        // Heuristic classification
        if (blockCount > 500) {
            return "REGIME_3A"; // Complex = potentially adversarial
        } else if (blockCount > 100) {
            return "REGIME_2"; // Medium complexity = sensor/internal state
        } else if (blockCount < 20) {
            return "REGIME_1"; // Simple = deterministic
        } else if (func.getName().toLowerCase().contains("crc") ||
                   func.getName().toLowerCase().contains("hash")) {
            return "PROVENANCE"; // Known table patterns
        } else {
            return "REGIME_2"; // Default to medium
        }
    }
}
