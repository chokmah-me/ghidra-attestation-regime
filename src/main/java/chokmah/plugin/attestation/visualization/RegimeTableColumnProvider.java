// RegimeTableColumnProvider.java
// Custom column in Ghidra's Symbol Table for sortable regime triage.
//
// Shows regime, confidence, and provenance score per function.
// Sort by regime to triage: Regime 3a first, then provenance checks,
// then Regime 2, Regime 1, unclassified.

package chokmah.plugin.attestation.visualization;

import chokmah.plugin.attestation.RegimeAnalyzerPlugin;
import chokmah.plugin.attestation.model.*;
import docking.widgets.table.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

import java.util.*;

/**
 * Provides a custom "Attestation Regime" column in Ghidra's Symbol Table.
 * Enables sorting and filtering functions by their regime classification.
 */
public class RegimeTableColumnProvider {

    private final RegimeAnalyzerPlugin plugin;

    public RegimeTableColumnProvider(RegimeAnalyzerPlugin plugin) {
        this.plugin = plugin;
    }

    public void dispose() {
        // Unregister column if registered
    }

    public void updateClassifications(Map<Address, ClassificationResult> results) {
        // TODO: trigger Symbol Table refresh to pick up new column data
    }

    /**
     * Dynamic table column for regime display.
     */
    public static class RegimeColumn
            extends DynamicTableColumnExtensionPoint<Symbol, RegimeCellData, Object> {

        private final RegimeAnalyzerPlugin plugin;

        public RegimeColumn(RegimeAnalyzerPlugin plugin) {
            this.plugin = plugin;
        }

        @Override
        public String getColumnName() {
            return "Attestation Regime";
        }

        @Override
        public Class<RegimeCellData> getColumnClass() {
            return RegimeCellData.class;
        }

        @Override
        public RegimeCellData getValueOf(Symbol symbol, Object settings,
                                         ServiceProvider sp) throws IllegalArgumentException {
            if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                return null;
            }

            Address entry = symbol.getAddress();
            ClassificationResult result = plugin.getClassification(entry);

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

        @Override
        public int getColumnPreferredWidth() {
            return 150;
        }
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
