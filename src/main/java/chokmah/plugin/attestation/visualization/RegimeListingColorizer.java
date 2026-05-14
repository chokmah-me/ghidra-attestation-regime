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
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.services.MarkerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Colorizes Ghidra's Listing view and Function Graph by attestation regime.
 */
public class RegimeListingColorizer {

    private final RegimeAnalyzerPlugin plugin;
    private final MarkerService markerService;
    private Map<Address, ClassificationResult> currentResults = new HashMap<>();
    private Map<String, ghidra.app.services.MarkerSet> markerSets = new HashMap<>();

    // ARGB colors matching AttestationRegime enum
    private static final Color COLOR_REGIME_1 = new Color(0x4C, 0xAF, 0x50, 0x40);   // green translucent
    private static final Color COLOR_REGIME_2 = new Color(0xFF, 0xEB, 0x3B, 0x40);   // yellow translucent
    private static final Color COLOR_REGIME_3A = new Color(0xF4, 0x43, 0x36, 0x50);  // red translucent
    private static final Color COLOR_PROVENANCE = new Color(0xFF, 0x98, 0x00, 0x50); // orange translucent
    private static final Color COLOR_UNCLASSIFIED = new Color(0x9E, 0x9E, 0x9E, 0x30); // gray translucent

    public RegimeListingColorizer(RegimeAnalyzerPlugin plugin, MarkerService markerService) {
        this.plugin = plugin;
        this.markerService = markerService;
    }

    public void dispose() {
        currentResults.clear();
        markerSets.clear();
    }

    public void updateClassifications(Map<Address, ClassificationResult> results, Program program) {
        this.currentResults = new HashMap<>(results);

        if (markerService != null && program != null && !results.isEmpty()) {
            // Clear old markers before creating new ones
            for (ghidra.app.services.MarkerSet ms : markerSets.values()) {
                markerService.removeMarker(ms, program);
            }
            markerSets.clear();

            // Create new markers for each regime
            for (AttestationRegime regime : AttestationRegime.values()) {
                ghidra.app.services.MarkerSet ms = markerService.createPointMarker(
                        "Regime_" + regime.name(), regime.getLabel(), program,
                        MarkerService.HIGHLIGHT_PRIORITY, true, true, false,
                        getColorForRegime(regime), null);

                for (Map.Entry<Address, ClassificationResult> entry : results.entrySet()) {
                    if (entry.getValue().getRegime() == regime) {
                        ms.add(entry.getKey());
                    }
                }
                markerSets.put(regime.name(), ms);
            }
        }
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
     * Apply regime colors to the Function Graph vertex backgrounds.
     * Accesses the FunctionGraphPlugin to color vertices per regime.
     * Note: FunctionGraphPlugin is internal to Ghidra; coloring is best-effort.
     */
    public void colorizeFunctionGraph(Program program,
                                      Map<Address, ClassificationResult> results) {
        if (plugin == null || plugin.getTool() == null || program == null) {
            return;
        }

        try {
            FunctionGraphPlugin fgPlugin = plugin.getTool().getService(FunctionGraphPlugin.class);
            if (fgPlugin == null) {
                return;
            }

            // Try to get the active Function Graph via reflection (internal API).
            // FunctionGraphPlugin does not expose a public getCurrentFunctionGraph() method in Ghidra 12.x.
            // This is a best-effort attempt; if the API differs, coloring silently skips.
            java.lang.reflect.Method getProviderMethod = null;
            try {
                getProviderMethod = fgPlugin.getClass().getMethod("getProvider");
            } catch (NoSuchMethodException e) {
                return; // API doesn't match; skip silently
            }

            Object provider = getProviderMethod.invoke(fgPlugin);
            if (provider == null) {
                return;
            }

            // Try to get the FunctionGraph from the provider
            java.lang.reflect.Method getGraphMethod = null;
            try {
                getGraphMethod = provider.getClass().getMethod("getFunctionGraph");
            } catch (NoSuchMethodException e) {
                return; // Provider doesn't expose getFunctionGraph; skip silently
            }

            Object graphObj = getGraphMethod.invoke(provider);
            if (graphObj == null || !(graphObj instanceof FunctionGraph)) {
                return;
            }

            FunctionGraph graph = (FunctionGraph) graphObj;

            // Apply colors to vertices
            for (Map.Entry<Address, ClassificationResult> entry : results.entrySet()) {
                Address addr = entry.getKey();
                ClassificationResult result = entry.getValue();
                Function func = program.getFunctionManager().getFunctionContaining(addr);

                if (func != null && func.getEntryPoint().equals(addr)) {
                    FGVertex vertex = graph.getVertexForAddress(addr);
                    if (vertex != null) {
                        Color color = getColorForRegime(result.getRegime());
                        vertex.setBackgroundColor(color);
                    }
                }
            }
        } catch (Exception e) {
            // FunctionGraphPlugin is internal; any API mismatch is silent to avoid noise
            // Coloring is a nice-to-have, not critical
        }
    }

    /**
     * Install margin markers in Listing view.
     * Creates colored margin markers for each regime class at function entry points.
     */
    public void installListingMarkers(Program program,
                                       Map<Address, ClassificationResult> results) {
        updateClassifications(results, program);
    }
}
