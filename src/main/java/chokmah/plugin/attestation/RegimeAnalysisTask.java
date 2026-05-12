// RegimeAnalysisTask.java
// Background task for running the classification pipeline on all functions.
// Runs in Ghidra's task thread to keep UI responsive.

package chokmah.plugin.attestation;

import chokmah.plugin.attestation.model.*;
import chokmah.plugin.attestation.analysis.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.task.*;

import java.util.*;
import java.util.function.Consumer;

/**
 * Ghidra background task that runs the 5-step classification pipeline.
 */
public class RegimeAnalysisTask extends Task {

    private final Program program;
    private final List<MemoryRegion> memoryMap;
    private final Consumer<Map<Address, ClassificationResult>> onComplete;

    public RegimeAnalysisTask(Program program, List<MemoryRegion> memoryMap,
                              Consumer<Map<Address, ClassificationResult>> onComplete) {
        super("Attestation Regime Classification", true, true, true);
        this.program = program;
        this.memoryMap = memoryMap;
        this.onComplete = onComplete;
    }

    @Override
    public void run(TaskMonitor monitor) {
        monitor.setMessage("Initializing decompiler...");

        // Initialize decompiler
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.openProgram(program);

        try {
            // Step 1-4: classify each function
            FunctionRegimeAnalyzer analyzer = new FunctionRegimeAnalyzer(
                    program, decompiler, memoryMap, monitor, false);

            monitor.setMessage("Running Steps 1-4 (per-function classification)...");
            Map<Address, ClassificationResult> step4Results =
                    analyzer.analyzeAllFunctions();

            if (monitor.isCancelled()) {
                return;
            }

            // Step 5: weighted propagation through call graph
            monitor.setMessage("Running Step 5 (weighted regime propagation)...");

            Map<Address, RegimeClassification> propagationInput = new HashMap<>();
            for (Map.Entry<Address, ClassificationResult> entry : step4Results.entrySet()) {
                ClassificationResult cr = entry.getValue();
                RegimeClassification rc = new RegimeClassification(
                        cr.getRegime(), cr.getConfidence());
                rc.setClassificationRationale(cr.getRationale());
                rc.setProvenanceCheckScore(cr.getProvenanceCheckScore());
                propagationInput.put(entry.getKey(), rc);
            }

            WeightedRegimePropagator propagator =
                    new WeightedRegimePropagator(program, monitor);

            Map<Address, RegimeClassification> propagated = propagator.propagate(
                    propagationInput, null, 10);

            // Merge propagation results back into ClassificationResults
            Map<Address, ClassificationResult> finalResults = new HashMap<>();
            for (Map.Entry<Address, ClassificationResult> entry : step4Results.entrySet()) {
                Address addr = entry.getKey();
                ClassificationResult original = entry.getValue();
                RegimeClassification propagatedClass = propagated.get(addr);

                if (propagatedClass != null &&
                        propagatedClass.getRegime() != original.getRegime()) {
                    // Regime changed via propagation
                    finalResults.put(addr, ClassificationResult.builder()
                            .regime(propagatedClass.getRegime())
                            .confidence(propagatedClass.getConfidence())
                            .inputSources(original.getInputSources())
                            .propagationPath(propagatedClass.getPropagationPath())
                            .loopsBounded(original.isLoopsBounded())
                            .hasIndirectControlFlow(original.isHasIndirectControlFlow())
                            .cyclomaticComplexity(original.getCyclomaticComplexity())
                            .lookupTableEntries(original.getLookupTableEntries())
                            .pcodeOpCount(original.getPcodeOpCount())
                            .provenanceCheckScore(original.getProvenanceCheckScore())
                            .rationale("[PROPAGATED] " + propagatedClass.getClassificationRationale() +
                                    " | " + original.getRationale())
                            .analysisTimeMs(original.getAnalysisTimeMs())
                            .build());
                } else {
                    finalResults.put(addr, original);
                }
            }

            monitor.setMessage("Classification complete.");

            // Notify completion on Swing thread
            if (onComplete != null) {
                javax.swing.SwingUtilities.invokeLater(() -> onComplete.accept(finalResults));
            }

        } finally {
            decompiler.dispose();
        }
    }
}
