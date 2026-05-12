// RegimeClassification.java
// Regime classification attached to a function.
// Can be persisted via Ghidra's property manager or exported to JSON reports.

package chokmah.plugin.attestation.model;

import java.util.*;

/**
 * Regime classification attached to a function.
 * Contains analysis results and provenance data per Section 4.
 *
 * Data model:
 * {
 *   regime: 1 | 2 | 3a | "provenance_check",
 *   confidence: HIGH | MEDIUM | LOW,
 *   input_sources: [...],
 *   propagation_path: [...],
 *   provenance_check_score: float  // only for flagged functions
 * }
 */
public class RegimeClassification {

    public static final String PROPERTY_NAME = "AttestationRegime";

    private AttestationRegime regime;
    private Confidence confidence;
    private final List<InputSource> inputSources;
    private final List<PropagationEdge> propagationPath;
    private double provenanceCheckScore;
    private double propagationWeight;
    private String classificationRationale;
    private long classificationTimestamp;

    public RegimeClassification() {
        this.regime = AttestationRegime.UNCLASSIFIED;
        this.confidence = Confidence.LOW;
        this.inputSources = new ArrayList<>();
        this.propagationPath = new ArrayList<>();
        this.provenanceCheckScore = 0.0;
        this.propagationWeight = 1.0;
        this.classificationRationale = "";
        this.classificationTimestamp = 0;
    }

    public RegimeClassification(AttestationRegime regime, Confidence confidence) {
        this();
        this.regime = regime;
        this.confidence = confidence;
        this.classificationTimestamp = System.currentTimeMillis();
    }

    public AttestationRegime getRegime() {
        return regime;
    }

    public void setRegime(AttestationRegime regime) {
        this.regime = regime;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    public void setConfidence(Confidence confidence) {
        this.confidence = confidence;
    }

    public List<InputSource> getInputSources() {
        return Collections.unmodifiableList(inputSources);
    }

    public void addInputSource(InputSource source) {
        this.inputSources.add(source);
    }

    public List<PropagationEdge> getPropagationPath() {
        return Collections.unmodifiableList(propagationPath);
    }

    public void addPropagationEdge(PropagationEdge edge) {
        this.propagationPath.add(edge);
    }

    public double getProvenanceCheckScore() {
        return provenanceCheckScore;
    }

    public void setProvenanceCheckScore(double score) {
        this.provenanceCheckScore = score;
    }

    public double getPropagationWeight() {
        return propagationWeight;
    }

    public void setPropagationWeight(double weight) {
        this.propagationWeight = weight;
    }

    public String getClassificationRationale() {
        return classificationRationale;
    }

    public void setClassificationRationale(String rationale) {
        this.classificationRationale = rationale;
    }

    public long getClassificationTimestamp() {
        return classificationTimestamp;
    }

    public void setClassificationTimestamp(long timestamp) {
        this.classificationTimestamp = timestamp;
    }

    /**
     * True if this classification was derived via propagation rather than
     * direct analysis of the function body.
     */
    public boolean isPropagated() {
        return !propagationPath.isEmpty();
    }

}
