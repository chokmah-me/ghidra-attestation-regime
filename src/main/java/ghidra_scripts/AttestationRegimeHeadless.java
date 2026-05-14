package ghidra_scripts;

import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import chokmah.plugin.attestation.analysis.*;
import chokmah.plugin.attestation.model.*;
import chokmah.plugin.attestation.parser.SvdMemoryMapParser;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AttestationRegimeHeadless extends GhidraScript {

    @Override
    protected void run() throws Exception {
        println("=== Attestation Regime Headless Analysis ===");

        // Load memory map if provided as script argument
        List<MemoryRegion> memoryMap = new ArrayList<>();
        String[] args = getScriptArgs();
        if (args.length > 0) {
            File mapFile = new File(args[0]);
            if (mapFile.exists()) {
                println("Loading memory map from: " + mapFile.getAbsolutePath());
                SvdMemoryMapParser parser = new SvdMemoryMapParser();
                memoryMap = parser.parseJsonMemoryMap(mapFile);
                println("Loaded " + memoryMap.size() + " memory regions");
            } else {
                println("Warning: memory map file not found: " + args[0]);
                println("Proceeding with heuristic Cortex-M defaults");
            }
        } else {
            println("No memory map provided. Using heuristic Cortex-M defaults.");
            println("Usage: AttestationRegimeHeadless.java <path/to/memory_map.json>");
        }

        // Instantiate analyzers
        ControlFlowAnalyzer cfa = new ControlFlowAnalyzer(currentProgram, monitor);
        ComplexityAnalyzer ca = new ComplexityAnalyzer(currentProgram, monitor);
        RegimeAssigner ra = new RegimeAssigner(false);
        InputSourceTagger tagger = new InputSourceTagger(currentProgram, monitor, memoryMap);

        // Decompiler
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;

        // Step 1-4: per-function classification
        Map<Address, ClassificationResult> step4Results = new HashMap<>();

        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function f = funcs.next();

            // Decompile
            DecompileResults results = decomp.decompileFunction(f, 30, monitor);
            if (!results.decompileCompleted()) {
                println("Skipping " + f.getName() + " — decompilation failed");
                continue;
            }

            // Gather input sources
            List<InputSource> sources = tagger.identifySources(f);

            // Analyze
            ControlFlowProperties cfp = cfa.analyze(f, results.getHighFunction());
            ComplexityMetrics cm = ca.analyze(f, results.getHighFunction());

            // Assign regime
            RegimeAssigner.RegimeAssignment assignment = ra.assignRegime(sources, cfp, cm);

            ClassificationResult cr = ClassificationResult.builder()
                    .regime(assignment.regime())
                    .confidence(assignment.confidence())
                    .inputSources(sources)
                    .rationale(assignment.rationale())
                    .loopsBounded(cfp.isLoopsBounded())
                    .hasIndirectControlFlow(cfp.hasIndirectControlFlow())
                    .cyclomaticComplexity(cm.getCyclomaticComplexity())
                    .lookupTableEntries(cm.getLookupTableEntries())
                    .pcodeOpCount(cm.getPcodeOpCount())
                    .build();

            step4Results.put(f.getEntryPoint(), cr);
            count++;
            monitor.setMessage("Analyzed " + count + " functions");
        }

        decomp.dispose();

        // Step 5: weighted regime propagation through call graph
        println("\nRunning Step 5: Weighted regime propagation...");

        Map<Address, RegimeClassification> propagationInput = new HashMap<>();
        for (Map.Entry<Address, ClassificationResult> entry : step4Results.entrySet()) {
            ClassificationResult cr = entry.getValue();
            RegimeClassification rc = new RegimeClassification(
                    cr.getRegime(), cr.getConfidence());
            rc.setClassificationRationale(cr.getRationale());
            propagationInput.put(entry.getKey(), rc);
        }

        WeightedRegimePropagator propagator = new WeightedRegimePropagator(currentProgram, monitor);
        Map<Address, RegimeClassification> propagated = propagator.propagate(propagationInput, null, 10);

        // Merge and print results
        println("\n=== Final Classifications (after propagation) ===");
        int r1 = 0, r2 = 0, r3a = 0, prov = 0, unclass = 0;

        for (Map.Entry<Address, ClassificationResult> entry : step4Results.entrySet()) {
            Address addr = entry.getKey();
            ClassificationResult original = entry.getValue();
            RegimeClassification propagatedClass = propagated.get(addr);

            AttestationRegime finalRegime = original.getRegime();
            String rationale = original.getRationale();

            if (propagatedClass != null && propagatedClass.getRegime() != original.getRegime()) {
                finalRegime = propagatedClass.getRegime();
                rationale = "[PROPAGATED] " + propagatedClass.getClassificationRationale();
            }

            Function f = currentProgram.getFunctionManager().getFunctionContaining(addr);
            if (f != null) {
                println(String.format("Function: %-30s | Regime: %-15s | Confidence: %s | %s",
                        f.getName(), finalRegime,
                        propagatedClass != null ? propagatedClass.getConfidence() : original.getConfidence(),
                        rationale));
            }

            switch (finalRegime) {
                case REGIME_1 -> r1++;
                case REGIME_2 -> r2++;
                case REGIME_3A -> r3a++;
                case PROVENANCE_CHECK -> prov++;
                case UNCLASSIFIED -> unclass++;
            }
        }

        println("\n=== Summary ===");
        println(String.format("Regime 1 (deterministic): %d", r1));
        println(String.format("Regime 2 (cooperative): %d", r2));
        println(String.format("Regime 3a (adversarial): %d", r3a));
        println(String.format("Provenance check: %d", prov));
        println(String.format("Unclassified: %d", unclass));
        println(String.format("Total: %d", step4Results.size()));

        // Write JSON output if path provided
        if (args.length >= 2 && args[1] != null && !args[1].isEmpty()) {
            String outputJsonPath = args[1];
            try {
                JsonObject root = new JsonObject();
                root.addProperty("firmware", currentProgram.getName());
                root.addProperty("totalFunctions", step4Results.size());

                JsonObject counts = new JsonObject();
                counts.addProperty("REGIME_1", r1);
                counts.addProperty("REGIME_2", r2);
                counts.addProperty("REGIME_3A", r3a);
                counts.addProperty("PROVENANCE", prov);
                counts.addProperty("UNCLASSIFIED", unclass);
                root.add("regimeCounts", counts);

                Files.write(Paths.get(outputJsonPath), root.toString().getBytes());
                println("\nResults written to: " + outputJsonPath);
            } catch (Exception e) {
                println("Warning: Could not write JSON output to " + args[1] + ": " + e.getMessage());
            }
        }
    }
}