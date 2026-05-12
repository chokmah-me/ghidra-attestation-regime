package ghidra_scripts;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import chokmah.plugin.attestation.analysis.*;
import chokmah.plugin.attestation.model.*;
import chokmah.plugin.attestation.parser.SvdMemoryMapParser;

import java.io.File;
import java.util.List;
import java.util.Map;

/**
 * Headless script: run the full attestation regime classification pipeline
 * and print results. Usage:
 *   analyzeHeadless . ProjectName -import firmware.elf
 *     -postScript AttestationRegimeHeadless.java path/to/memory_map.json
 *     -scriptPath ghidra_scripts -deleteProject
 */
public class AttestationRegimeHeadless extends GhidraScript {

    @Override
    protected void run() throws Exception {
        println("=== Attestation Regime Headless Analysis ===");

        // Load memory map from script argument
        List<MemoryRegion> memoryMap = null;
        String[] args = getScriptArgs();

        if (args != null && args.length > 0) {
            File mapFile = new File(args[0]);
            if (mapFile.exists()) {
                try {
                    memoryMap = SvdMemoryMapParser.loadJsonMemoryMap(mapFile);
                    println("Loaded memory map from: " + args[0] + " (" + memoryMap.size() + " regions)");
                } catch (Exception e) {
                    println("Failed to load memory map: " + e.getMessage());
                    memoryMap = null;
                }
            } else {
                println("Memory map file not found: " + args[0]);
            }
        }

        if (memoryMap == null) {
            println("WARNING: No memory map provided. Using heuristic Cortex-M defaults (70% accuracy).");
            memoryMap = InputSourceTagger.getCortexMHeuristicMap(currentProgram);
        }

        // Initialize decompiler
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        try {
            // Run the full classification pipeline
            FunctionRegimeAnalyzer analyzer = new FunctionRegimeAnalyzer(
                currentProgram, decomp, memoryMap, monitor, false);

            Map<Address, ClassificationResult> results = analyzer.analyzeAllFunctions();

            // Print results
            println("");
            println("=== Classification Results ===");
            println(String.format("%-10s %-40s %-15s %-10s %s",
                "Address", "Function", "Regime", "Confidence", "Rationale"));
            println("-".repeat(120));

            int regime1 = 0, regime2 = 0, regime3a = 0, prov = 0, unclass = 0;

            for (Map.Entry<Address, ClassificationResult> entry : results.entrySet()) {
                Address addr = entry.getKey();
                ClassificationResult result = entry.getValue();
                String funcName = currentProgram.getFunctionManager().getFunctionAt(addr).getName();

                println(String.format("0x%-8x %-40s %-15s %-10s %s",
                    addr.getOffset(),
                    funcName.length() > 40 ? funcName.substring(0, 37) + "..." : funcName,
                    result.getRegime(),
                    result.getConfidence(),
                    result.getRationale().length() > 40
                        ? result.getRationale().substring(0, 37) + "..."
                        : result.getRationale()));

                switch (result.getRegime()) {
                    case REGIME_1 -> regime1++;
                    case REGIME_2 -> regime2++;
                    case REGIME_3A -> regime3a++;
                    case PROVENANCE -> prov++;
                    default -> unclass++;
                }
            }

            println("");
            println("=== Summary ===");
            println(String.format("Regime 1 (Formally Provable):      %4d functions (%.1f%%)",
                regime1, 100.0 * regime1 / results.size()));
            println(String.format("Regime 2 (Statistically Testable): %4d functions (%.1f%%)",
                regime2, 100.0 * regime2 / results.size()));
            println(String.format("Regime 3a (Adversarial Input):     %4d functions (%.1f%%)",
                regime3a, 100.0 * regime3a / results.size()));
            println(String.format("Provenance Check:                  %4d functions (%.1f%%)",
                prov, 100.0 * prov / results.size()));
            println(String.format("Unclassified:                      %4d functions (%.1f%%)",
                unclass, 100.0 * unclass / results.size()));
            println(String.format("Total:                             %4d functions", results.size()));

        } finally {
            decomp.dispose();
        }

        println("=== Complete ===");
    }
}
