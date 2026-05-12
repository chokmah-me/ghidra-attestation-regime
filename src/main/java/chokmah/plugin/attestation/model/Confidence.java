// Confidence.java
// Per-function classification confidence level

package chokmah.plugin.attestation.model;

/**
 * Confidence reflects the quality of evidence backing a regime assignment.
 *
 * HIGH:   SVD-annotated memory map, clean decompilation, bounded loops verified.
 * MEDIUM: Heuristic memory map (standard Cortex-M ranges), some MMIO access
 *         ambiguity, or propagation-derived classification.
 * LOW:    Stripped binary, no memory map, heavy reliance on conservative
 *         defaults (unclassified external reads default to Regime 3a).
 */
public enum Confidence {
    HIGH,
    MEDIUM,
    LOW
}
