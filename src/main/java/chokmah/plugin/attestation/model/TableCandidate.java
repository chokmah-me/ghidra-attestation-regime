package chokmah.plugin.attestation.model;

/**
 * A discovered constant table reference with provenance status.
 * tableOffset is the memory address as a long to avoid Ghidra Address dependency.
 */
public record TableCandidate(
        long tableOffset,
        int totalBytes,
        int entrySize,
        int entryCount,
        KnownConstantTables.TableMatch knownMatch,
        boolean isUnexplained  // true if no known match -> provenance flag
) {
}
