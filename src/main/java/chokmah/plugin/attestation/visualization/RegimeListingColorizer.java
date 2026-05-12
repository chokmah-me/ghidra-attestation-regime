// RegimeListingColorizer.java
// Color-code functions in Ghidra's Listing and Function Graph views.
//
// Green  = Regime 1 (formally verifiable)
// Yellow = Regime 2 (statistical testing applies)
// Red    = Regime 3a (adversarial input exposure)
// Orange = Provenance check flag (large unexplained tables)
// Gray   = Unclassified (insufficient memory map data)
//
// Uses Ghidra's colorizing service to highlight function headers and
// basic blocks with regime-specific colors.

package chokmah.plugin.attestation.visualization;

import chokmah.plugin.attestation.RegimeAnalyzerPlugin;
import chokmah.plugin.attestation.model.*;
import ghidra.app.decompiler.component.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Colorizes Ghidra's Listing view and Function Graph by attestation regime.
 */
public class RegimeListingColorizer {

    private final RegimeAnalyzerPlugin plugin;

    // ARGB colors matching AttestationRegime enum
    private static final Color COLOR_REGIME_1 = new Color(0x4C, 0xAF, 0x50, 0x40);   // green translucent
    private static final Color COLOR_REGIME_2 = new Color(0xFF, 0xEB, 0x3B, 0x40);   // yellow translucent
    private static final Color COLOR_REGIME_3A = new Color(0xF4, 0x43, 0x36, 0x50);  // red translucent
    private static final Color COLOR_PROVENANCE = new Color(0xFF, 0x98, 0x00, 0x50); // orange translucent
    private static final Color COLOR_UNCLASSIFIED = new Color(0x9E, 0x9E, 0x9E, 0x30); // gray translucent

    public RegimeListingColorizer(RegimeAnalyzerPlugin plugin) {
        this.plugin = plugin;
    }

    public void dispose() {
        // Unregister colorizers
    }

    public void updateClassifications(Map<Address, ClassificationResult> results) {
        // TODO: trigger Listing and Function Graph repaint
        // Ghidra's colorizing is typically done via:
        // 1. MarkerService for margin markers
        // 2. ListingModel for background color
        // 3. FunctionGraphService for graph node colors
    }

    /**
     * Get display color for a regime.
     */
    public static Color getColorForRegime(AttestationRegime regime) {
        return switch (regime) {
            case REGIME_1 -> COLOR_REGIME_1;
            case REGIME_2 -> COLOR_REGIME_2;
            case REGIME_3A -> COLOR_REGIME_3A;
            case PROVENANCE_CHECK -> COLOR_PROVENANCE;
            case UNCLASSIFIED -> COLOR_UNCLASSIFIED;
        };
    }

    /**
     * Get HTML color string for report generation.
     */
    public static String getHtmlColorForRegime(AttestationRegime regime) {
        return switch (regime) {
            case REGIME_1 -> "#4CAF50";
            case REGIME_2 -> "#FFEB3B";
            case REGIME_3A -> "#F44336";
            case PROVENANCE_CHECK -> "#FF9800";
            case UNCLASSIFIED -> "#9E9E9E";
        };
    }

    /**
     * Apply regime colors to the Function Graph.
     * Each basic block colored by its containing function's regime.
     */
    public void colorizeFunctionGraph(Program program,
                                      Map<Address, ClassificationResult> results) {
        // TODO: implement via FunctionGraphService
        // 1. Get FunctionGraph for current function
        // 2. For each vertex (basic block), find containing function
        // 3. Apply regime color to vertex background
    }

    /**
     * Install margin markers in Listing view.
     */
    public void installListingMarkers(Program program,
                                       Map<Address, ClassificationResult> results) {
        // TODO: implement via MarkerService
        // 1. For each classified function, add a colored marker at entry point
        // 2. Marker tooltip shows regime label and rationale
    }
}
