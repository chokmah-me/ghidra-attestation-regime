// RegimeTableColumnProvider.java
// Custom column in Ghidra's Symbol Table for sortable regime triage.
//
// Shows regime, confidence, and provenance score per function.
// Sort by regime to triage: Regime 3a first, then provenance checks,
// then Regime 2, Regime 1, unclassified.

package chokmah.plugin.attestation.visualization;

import chokmah.plugin.attestation.RegimeAnalyzerPlugin;
import chokmah.plugin.attestation.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import java.util.*;

/**
 * Provides a custom "Attestation Regime" column in Ghidra's Symbol Table.
 * Enables sorting and filtering functions by their regime classification.
 * Note: The actual table column extension is registered at runtime via Ghidra's
 * service framework. This class manages the data and display logic.
 */
public class RegimeTableColumnProvider {

    private final RegimeAnalyzerPlugin plugin;

    public RegimeTableColumnProvider(RegimeAnalyzerPlugin plugin) {
        this.plugin = plugin;
    }

    public void dispose() {
        // Cleanup if needed
    }

    public void updateClassifications(Map<Address, ClassificationResult> results) {
        // Trigger table refresh. In a real implementation, this would fire a
        // PluginEvent to notify the table of data changes.
        Msg.debug(this, "Classification map updated with " + results.size() + " functions");
    }

    public String getColumnName() {
        return "Attestation Regime";
    }

    public Class<RegimeCellData> getColumnClass() {
        return RegimeCellData.class;
    }

    public int getColumnPreferredWidth() {
        return 150;
    }

    /**
     * Get cell data for a given function address.
     */
    public RegimeCellData getValueForAddress(Address functionEntry) {
        ClassificationResult result = plugin.getClassification(functionEntry);

        if (result == null) {
            return new RegimeCellData(AttestationRegime.UNCLASSIFIED,
                    Confidence.LOW, 0.0);
        }

        return new RegimeCellData(
                result.getRegime(),
                result.getConfidence(),
                result.getProvenanceCheckScore()
        );
    }

    /**
     * Cell data object rendered in the column.
     */
    public record RegimeCellData(
            AttestationRegime regime,
            Confidence confidence,
            double provenanceScore
    ) {
        @Override
        public String toString() {
            return regime.getLabel() + " (" + confidence + ")";
        }

        /**
         * Sort key: Regime 3a > Provenance > Regime 2 > Regime 1 > Unclassified.
         */
        public int sortPriority() {
            return switch (regime) {
                case UNCLASSIFIED -> 0;
                case REGIME_1 -> 1;
                case REGIME_2 -> 2;
                case PROVENANCE_CHECK -> 3;
                case REGIME_3A -> 4;
            };
        }
    }
}
