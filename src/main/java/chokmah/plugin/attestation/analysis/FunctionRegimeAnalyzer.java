// FunctionRegimeAnalyzer.java
// Orchestrator: runs the 5-step classification pipeline per function
//
// Pipeline:
//   Step 1: InputSourceTagger     -> tag data sources
//   Step 2: ControlFlowAnalyzer   -> loop bounds, indirect CF
//   Step 3: ComplexityAnalyzer    -> cyclomatic, table size, pcode ops
//   Step 4: RegimeAssigner        -> decision tree assignment
//   Step 5: WeightedRegimePropagator -> call-graph propagation (global)
//
// The plugin is a mid-analysis tool, not a first-pass tool. Requires
// memory map annotation (SVD or manual JSON) for meaningful results.

package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Main analysis orchestrator. Runs Steps 1-4 per function.
 * Step 5 (propagation) is run globally after all functions are classified.
 */
public class FunctionRegimeAnalyzer {

    private final Program program;
    private final DecompInterface decompiler;
    private final List<MemoryRegion> memoryMap;
    private final TaskMonitor monitor;
    private final boolean strictMode;

    private final InputSourceTagger tagger;
    private final ControlFlowAnalyzer cfAnalyzer;
    private final ComplexityAnalyzer complexityAnalyzer;
    private final RegimeAssigner regimeAssigner;

    public FunctionRegimeAnalyzer(Program program, DecompInterface decompiler,
                                  List<MemoryRegion> memoryMap,
                                  TaskMonitor monitor, boolean strictMode) {
        this.program = program;
        this.decompiler = decompiler;
        this.memoryMap = memoryMap != null ? memoryMap : Collections.emptyList();
        this.monitor = monitor;
        this.strictMode = strictMode;

        this.tagger = new InputSourceTagger(program, this.memoryMap, monitor);
        this.cfAnalyzer = new ControlFlowAnalyzer(program, this.memoryMap, monitor);
        this.complexityAnalyzer = new ComplexityAnalyzer(program, monitor);
        this.regimeAssigner = new RegimeAssigner(strictMode);
    }

    /**
     * Run Steps 1-4 on a single function.
     *
     * @param function the function to analyze
     * @return classification result with all metrics
     */
    public ClassificationResult analyzeFunction(Function function) {
        long startTime = System.currentTimeMillis();

        // Decompile function
        DecompileResults decompResult = decompiler.decompileFunction(
                function, decompiler.getOptions().getDefaultTimeout(), monitor);

        HighFunction highFunction = decompResult != null ?
                decompResult.getHighFunction() : null;

        // Step 1: Input source tagging
        List<InputSource> sources = tagger.tagFunctionInputs(function, highFunction);

        // Step 2: Control flow analysis
        ControlFlowProperties cfProps =
                cfAnalyzer.analyze(function, highFunction);

        // Step 3: Complexity assessment
        ComplexityMetrics complexity =
                complexityAnalyzer.analyze(function, highFunction);

        // Step 4: Regime assignment
        RegimeAssigner.RegimeAssignment assignment =
                regimeAssigner.assignRegime(sources, cfProps, complexity);

        long elapsed = System.currentTimeMillis() - startTime;

        // Build result
        Confidence confidence = determineConfidence(assignment.confidence(),
                highFunction != null, !memoryMap.isEmpty());

        return ClassificationResult.builder()
                .regime(assignment.regime())
                .confidence(confidence)
                .inputSources(sources)
                .loopsBounded(cfProps.allLoopsBounded())
                .hasIndirectControlFlow(cfProps.hasIndirectControlFlow())
                .cyclomaticComplexity(complexity.cyclomaticComplexity())
                .lookupTableEntries(complexity.lookupTableEntries())
                .pcodeOpCount(complexity.pcodeOpCount())
                .provenanceCheckScore(complexity.provenanceCheckScore())
                .rationale(buildFullRationale(assignment, cfProps, complexity))
                .analysisTimeMs(elapsed)
                .build();
    }

    /**
     * Run classification on all functions in the program.
     *
     * @return map of function entry address -> classification
     */
    public Map<Address, ClassificationResult> analyzeAllFunctions() {
        Map<Address, ClassificationResult> results = new HashMap<>();
        FunctionManager funcMgr = program.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        int total = funcMgr.getFunctionCount();
        int current = 0;

        monitor.initialize(total);
        monitor.setMessage("Classifying functions into attestation regimes...");

        Map<Address, List<InputSource>> priorInputSources = new HashMap<>();
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            current++;
            monitor.setProgress(current);
            monitor.setMessage(String.format("Analyzing %s (%d/%d)",
                    func.getName(), current, total));

            try {
                tagger.setPriorResults(priorInputSources);
                ClassificationResult result = analyzeFunction(func);
                results.put(func.getEntryPoint(), result);
                priorInputSources.put(func.getEntryPoint(), result.getInputSources());

                // Store in Ghidra's property manager for persistence
                storeClassification(func, result);

            } catch (Exception e) {
                // Log error but continue analysis
                monitor.setMessage(String.format("Error analyzing %s: %s",
                        func.getName(), e.getMessage()));
            }
        }

        return results;
    }

    /**
     * Store classification in Ghidra's property manager for persistence
     * across sessions. (TODO: v0.4.0 - requires RegimeClassification to implement Saveable)
     */
    private void storeClassification(Function function, ClassificationResult result) {
        try {
            RegimeClassification saveable = new RegimeClassification(
                    result.getRegime(), result.getConfidence());
            saveable.setClassificationRationale(result.getRationale());
            saveable.setProvenanceCheckScore(result.getProvenanceCheckScore());
            saveable.setClassificationTimestamp(System.currentTimeMillis());

            for (InputSource src : result.getInputSources()) {
                saveable.addInputSource(src);
            }

            // TODO: enable PropertyMapManager wiring for persistence in v0.4.0
            // Currently blocked on RegimeClassification implementing Saveable interface
            // program.withTransaction("Store regime classification", () -> {
            //     var pmgr = program.getUsrPropertyManager();
            //     var propMap = pmgr.getObjectPropertyMap(RegimeClassification.PROPERTY_NAME);
            //     if (propMap == null) {
            //         propMap = pmgr.createObjectPropertyMap(
            //             RegimeClassification.PROPERTY_NAME, RegimeClassification.class);
            //     }
            //     propMap.add(function.getEntryPoint(), saveable);
            // });
        } catch (Exception e) {
            // Property storage failed; classification exists in memory only
        }
    }

    /**
     * Confidence adjustment based on analysis quality factors.
     */
    private Confidence determineConfidence(Confidence base, boolean decompiled,
                                          boolean hasMemoryMap) {
        if (!decompiled) {
            // Raw analysis without decompilation: lower confidence
            return Confidence.LOW;
        }
        if (!hasMemoryMap) {
            // Heuristic memory map only: cap at MEDIUM
            if (base == Confidence.HIGH) return Confidence.MEDIUM;
        }
        return base;
    }

    private String buildFullRationale(RegimeAssigner.RegimeAssignment assignment,
                                     ControlFlowProperties cfProps,
                                     ComplexityMetrics complexity) {
        StringBuilder sb = new StringBuilder();
        sb.append(assignment.rationale());
        sb.append(" | Loops: ").append(cfProps.loopCount());
        sb.append(" bounded=").append(cfProps.allLoopsBounded());
        sb.append(" | IndirectCF=").append(cfProps.hasIndirectControlFlow());
        sb.append(" | Cyclomatic=").append(complexity.cyclomaticComplexity());
        sb.append(" | Tables=").append(complexity.lookupTableEntries());
        sb.append(" | PcodeOps=").append(complexity.pcodeOpCount());
        return sb.toString();
    }
}
