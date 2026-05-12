// RegimeClassification.java
// Ghidra Saveable for persisting regime classification per function
// Stored via Ghidra's property manager as function-level metadata

package chokmah.plugin.attestation.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Saveable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.*;

/**
 * Persistent regime classification attached to a function.
 * Stored via PropertyMapManager using custom Saveable serialization.
 *
 * Data model per Section 4:
 * {
 *   regime: 1 | 2 | 3a | "provenance_check",
 *   confidence: HIGH | MEDIUM | LOW,
 *   input_sources: [...],
 *   propagation_path: [...],
 *   provenance_check_score: float  // only for flagged functions
 * }
 */
public class RegimeClassification implements Saveable {

    public static final String PROPERTY_NAME = "AttestationRegime";

    private AttestationRegime regime;
    private Confidence confidence;
    private final List<InputSource> inputSources;
    private final List<PropagationEdge> propagationPath;
    private double provenanceCheckScore;
    private double propagationWeight;
    private String classificationRationale;
    private long classificationTimestamp;

    // Ghidra Saveable protocol version
    private static final int SAVEABLE_VERSION = 1;

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

    // ---- Saveable implementation for Ghidra persistence ----

    @Override
    public Class<?>[] getObjectStorageFields() {
        return new Class<?>[] {
            String.class,      // regime label
            String.class,      // confidence label
            String.class,      // JSON-serialized input sources
            String.class,      // JSON-serialized propagation path
            Double.class,      // provenance check score
            Double.class,      // propagation weight
            String.class,      // rationale
            Long.class         // timestamp
        };
    }

    @Override
    public void save(ObjectStorage objStorage) {
        objStorage.putString(regime != null ? regime.name() : AttestationRegime.UNCLASSIFIED.name());
        objStorage.putString(confidence != null ? confidence.name() : Confidence.LOW.name());
        objStorage.putString(serializeInputSources());
        objStorage.putString(serializePropagationPath());
        objStorage.putDouble(provenanceCheckScore);
        objStorage.putDouble(propagationWeight);
        objStorage.putString(classificationRationale);
        objStorage.putLong(classificationTimestamp);
    }

    @Override
    public void restore(ObjectStorage objStorage) {
        String regimeName = objStorage.getString();
        String confidenceName = objStorage.getString();
        String sourcesJson = objStorage.getString();
        String pathJson = objStorage.getString();
        this.provenanceCheckScore = objStorage.getDouble();
        this.propagationWeight = objStorage.getDouble();
        this.classificationRationale = objStorage.getString();
        this.classificationTimestamp = objStorage.getLong();

        try {
            this.regime = AttestationRegime.valueOf(regimeName);
        } catch (IllegalArgumentException e) {
            this.regime = AttestationRegime.UNCLASSIFIED;
        }

        try {
            this.confidence = Confidence.valueOf(confidenceName);
        } catch (IllegalArgumentException e) {
            this.confidence = Confidence.LOW;
        }

        this.inputSources.clear();
        this.propagationPath.clear();
        // TODO: deserialize sourcesJson and pathJson on restore
    }

    @Override
    public int getSchemaVersion() {
        return SAVEABLE_VERSION;
    }

    @Override
    public boolean isUpgradeable(int oldSchemaVersion) {
        return oldSchemaVersion < SAVEABLE_VERSION;
    }

    @Override
    public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
                           ObjectStorage newObjStorage) throws IOException, CancelledException {
        return false;  // no upgrades defined yet
    }

    // ---- Serialization helpers (placeholder for JSON impl) ----

    private String serializeInputSources() {
        // TODO: JSON serialize inputSources list
        return "";
    }

    private String serializePropagationPath() {
        // TODO: JSON serialize propagationPath list
        return "";
    }
}
