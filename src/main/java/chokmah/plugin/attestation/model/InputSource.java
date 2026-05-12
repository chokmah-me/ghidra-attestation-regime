// InputSource.java
// Categorization of a function's ultimate data sources

package chokmah.plugin.attestation.model;

import ghidra.program.model.address.Address;

/**
 * Traces a function's data inputs back to their ultimate source.
 * Categories correspond to regime-determining sources per Section 3 Step 1.
 */
public class InputSource {

    public enum SourceType {
        CONSTANT,           // Hardcoded / ROM (neutral)
        INTERNAL_STATE,     // Global written by classified function -> inherit
        SENSOR_ADC,         // Reads from known sensor peripheral -> Regime 2
        NETWORK_COMMS,      // Reads from UART/Ethernet/MAC -> Regime 3a
        UNCLASSIFIED_EXT,   // Unannotated memory region -> conservative Regime 3a
        MMIO_UNKNOWN        // Known MMIO but untyped peripheral -> Regime 3a
    }

    private final SourceType sourceType;
    private final Address accessAddress;
    private final String description;
    private final AttestationRegime inheritedRegime;

    public InputSource(SourceType sourceType, Address accessAddress, String description) {
        this(sourceType, accessAddress, description, null);
    }

    public InputSource(SourceType sourceType, Address accessAddress,
                       String description, AttestationRegime inheritedRegime) {
        this.sourceType = sourceType;
        this.accessAddress = accessAddress;
        this.description = description;
        this.inheritedRegime = inheritedRegime;
    }

    public SourceType getSourceType() {
        return sourceType;
    }

    public Address getAccessAddress() {
        return accessAddress;
    }

    public String getDescription() {
        return description;
    }

    public AttestationRegime getInheritedRegime() {
        return inheritedRegime;
    }

    /**
     * Maps source type to default regime classification.
     * Internal state defers to inherited regime; constant is neutral (Regime 1).
     */
    public AttestationRegime defaultRegime() {
        return switch (sourceType) {
            case CONSTANT -> AttestationRegime.REGIME_1;
            case INTERNAL_STATE -> inheritedRegime != null
                ? inheritedRegime : AttestationRegime.UNCLASSIFIED;
            case SENSOR_ADC -> AttestationRegime.REGIME_2;
            case NETWORK_COMMS, UNCLASSIFIED_EXT, MMIO_UNKNOWN -> AttestationRegime.REGIME_3A;
        };
    }
}
