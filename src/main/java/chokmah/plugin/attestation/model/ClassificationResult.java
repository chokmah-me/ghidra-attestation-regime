// ClassificationResult.java
// Immutable result of the 5-step classification pipeline for a single function

package chokmah.plugin.attestation.model;

import java.util.*;

/**
 * Complete classification result for one function, produced by
 * FunctionRegimeAnalyzer after all 5 pipeline steps.
 */
public class ClassificationResult {

    private final AttestationRegime regime;
    private final Confidence confidence;
    private final List<InputSource> inputSources;
    private final List<PropagationEdge> propagationPath;
    private final double provenanceCheckScore;
    private final boolean loopsBounded;
    private final boolean hasIndirectControlFlow;
    private final int cyclomaticComplexity;
    private final int lookupTableEntries;
    private final int pcodeOpCount;
    private final String rationale;
    private final long analysisTimeMs;

    private ClassificationResult(Builder builder) {
        this.regime = builder.regime;
        this.confidence = builder.confidence;
        this.inputSources = Collections.unmodifiableList(builder.inputSources);
        this.propagationPath = Collections.unmodifiableList(builder.propagationPath);
        this.provenanceCheckScore = builder.provenanceCheckScore;
        this.loopsBounded = builder.loopsBounded;
        this.hasIndirectControlFlow = builder.hasIndirectControlFlow;
        this.cyclomaticComplexity = builder.cyclomaticComplexity;
        this.lookupTableEntries = builder.lookupTableEntries;
        this.pcodeOpCount = builder.pcodeOpCount;
        this.rationale = builder.rationale;
        this.analysisTimeMs = builder.analysisTimeMs;
    }

    public AttestationRegime getRegime() {
        return regime;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    public List<InputSource> getInputSources() {
        return inputSources;
    }

    public List<PropagationEdge> getPropagationPath() {
        return propagationPath;
    }

    public double getProvenanceCheckScore() {
        return provenanceCheckScore;
    }

    public boolean isLoopsBounded() {
        return loopsBounded;
    }

    public boolean isHasIndirectControlFlow() {
        return hasIndirectControlFlow;
    }

    public int getCyclomaticComplexity() {
        return cyclomaticComplexity;
    }

    public int getLookupTableEntries() {
        return lookupTableEntries;
    }

    public int getPcodeOpCount() {
        return pcodeOpCount;
    }

    public String getRationale() {
        return rationale;
    }

    public long getAnalysisTimeMs() {
        return analysisTimeMs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private AttestationRegime regime = AttestationRegime.UNCLASSIFIED;
        private Confidence confidence = Confidence.LOW;
        private List<InputSource> inputSources = new ArrayList<>();
        private List<PropagationEdge> propagationPath = new ArrayList<>();
        private double provenanceCheckScore = 0.0;
        private boolean loopsBounded = false;
        private boolean hasIndirectControlFlow = false;
        private int cyclomaticComplexity = 0;
        private int lookupTableEntries = 0;
        private int pcodeOpCount = 0;
        private String rationale = "";
        private long analysisTimeMs = 0;

        public Builder regime(AttestationRegime regime) {
            this.regime = regime;
            return this;
        }

        public Builder confidence(Confidence confidence) {
            this.confidence = confidence;
            return this;
        }

        public Builder inputSources(List<InputSource> sources) {
            this.inputSources = new ArrayList<>(sources);
            return this;
        }

        public Builder propagationPath(List<PropagationEdge> path) {
            this.propagationPath = new ArrayList<>(path);
            return this;
        }

        public Builder provenanceCheckScore(double score) {
            this.provenanceCheckScore = score;
            return this;
        }

        public Builder loopsBounded(boolean bounded) {
            this.loopsBounded = bounded;
            return this;
        }

        public Builder hasIndirectControlFlow(boolean hasIndirect) {
            this.hasIndirectControlFlow = hasIndirect;
            return this;
        }

        public Builder cyclomaticComplexity(int complexity) {
            this.cyclomaticComplexity = complexity;
            return this;
        }

        public Builder lookupTableEntries(int entries) {
            this.lookupTableEntries = entries;
            return this;
        }

        public Builder pcodeOpCount(int count) {
            this.pcodeOpCount = count;
            return this;
        }

        public Builder rationale(String rationale) {
            this.rationale = rationale;
            return this;
        }

        public Builder analysisTimeMs(long ms) {
            this.analysisTimeMs = ms;
            return this;
        }

        public ClassificationResult build() {
            return new ClassificationResult(this);
        }
    }
}
