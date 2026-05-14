// RegimeAnalyzerPlugin.java
// Ghidra Plugin: Attestation Regime Classifier
//
// Cross-Pollination H: Capability Attestation <-> Computability Filter <-> Shibboleth Lattice
// Bilar 2026 (#24, #2, #23, #5, #14, #16)
//
// Instantiates the Computability Filter as a binary triage tool for
// ICS/embedded firmware. Classifies every function into one of three
// attestation regimes before any analyst-hour is spent.
//
// Installation:
//   1. Build: gradle buildExtension
//   2. Install via File > Install Extensions > Add
//   3. Or copy dist/AttestationRegimeClassifier-*.zip to Ghidra/Extensions
//
// Usage:
//   1. Import firmware binary, analyze with Ghidra
//   2. Mark MMIO regions as volatile (critical for accuracy)
//   3. Load SVD file or JSON memory map (optional, enables heuristic fallback)
//   4. Tools > Attestation Regime > Classify All Functions
//   5. Review color-coded Listing and Function Graph views
//   6. Tools > Attestation Regime > Generate Report

package chokmah.plugin.attestation;

import chokmah.plugin.attestation.model.*;
import chokmah.plugin.attestation.analysis.*;
import chokmah.plugin.attestation.parser.SvdMemoryMapParser;
import chokmah.plugin.attestation.report.RegimeReportGenerator;
import chokmah.plugin.attestation.visualization.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

import java.io.File;
import java.util.*;

/**
 * Main Ghidra plugin for Attestation Regime Classification.
 */
@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = "AttestationRegime",
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Classify functions into attestation regimes",
        description = "Computability-Bounded Firmware Triage: " +
                "Attestation Regime Classification for Embedded Safety Systems. " +
                "Classifies every function into Regime 1 (deterministic), " +
                "Regime 2 (cooperative stochastic), or Regime 3 (adversarial) " +
                "based on input source analysis and control flow properties.",
        servicesRequired = { CodeViewerService.class }
)
public class RegimeAnalyzerPlugin extends ProgramPlugin {

    private DockingAction classifyAction;
    private DockingAction loadSvdAction;
    private DockingAction loadJsonAction;
    private DockingAction generateReportAction;
    private DockingAction clearAction;

    private List<MemoryRegion> memoryMap = new ArrayList<>();
    private Map<Address, ClassificationResult> results = new HashMap<>();
    private String lastLoadedSvdPath = "";

    private RegimeTableColumnProvider tableColumnProvider;
    private RegimeListingColorizer listingColorizer;

    public RegimeAnalyzerPlugin(PluginTool tool) {
        super(tool);
        createActions();
    }

    @Override
    protected void init() {
        super.init();

        // Install visualization components
        tableColumnProvider = new RegimeTableColumnProvider(this);
        MarkerService markerService = tool.getService(MarkerService.class);
        listingColorizer = new RegimeListingColorizer(this, markerService);

        // Try to load memory map from project data
        loadMemoryMapFromProject();
    }

    @Override
    protected void programOpened(Program program) {
        loadClassificationsFromPropertyMap(program);
    }

    @Override
    protected void programClosed(Program program) {
        results.clear();
        if (listingColorizer != null) {
            listingColorizer.clearClassifications();
        }
    }

    @Override
    public void dispose() {
        if (tableColumnProvider != null) {
            tableColumnProvider.dispose();
        }
        if (listingColorizer != null) {
            listingColorizer.dispose();
        }
        super.dispose();
    }

    private void createActions() {
        // Classify All Functions
        classifyAction = new DockingAction("Classify All Functions", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                runClassification();
            }
        };
        classifyAction.setMenuBarData(new MenuData(
                new String[]{"Attestation Regime", "Classify All Functions"},
                null, "AttestationRegime"));
        classifyAction.setDescription("Run 5-step classification pipeline on all functions");
        classifyAction.setEnabled(true);
        tool.addAction(classifyAction);

        // Load SVD File
        loadSvdAction = new DockingAction("Load SVD Memory Map", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                loadSvdFile();
            }
        };
        loadSvdAction.setMenuBarData(new MenuData(
                new String[]{"Attestation Regime", "Load SVD File..."},
                null, "AttestationRegime"));
        loadSvdAction.setDescription("Load ARM CMSIS-SVD peripheral description");
        loadSvdAction.setEnabled(true);
        tool.addAction(loadSvdAction);

        // Load JSON Memory Map
        loadJsonAction = new DockingAction("Load JSON Memory Map", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                loadJsonFile();
            }
        };
        loadJsonAction.setMenuBarData(new MenuData(
                new String[]{"Attestation Regime", "Load JSON Memory Map..."},
                null, "AttestationRegime"));
        loadJsonAction.setDescription("Load manual memory map annotation");
        loadJsonAction.setEnabled(true);
        tool.addAction(loadJsonAction);

        // Generate Report
        generateReportAction = new DockingAction("Generate Report", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                generateReport();
            }
        };
        generateReportAction.setMenuBarData(new MenuData(
                new String[]{"Attestation Regime", "Generate Report..."},
                null, "AttestationRegime"));
        generateReportAction.setDescription("Generate Markdown classification report");
        generateReportAction.setEnabled(true);
        tool.addAction(generateReportAction);

        // Clear Classifications
        clearAction = new DockingAction("Clear Classifications", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                clearClassifications();
            }
        };
        clearAction.setMenuBarData(new MenuData(
                new String[]{"Attestation Regime", "Clear Classifications"},
                null, "AttestationRegime"));
        clearAction.setDescription("Remove all regime classifications");
        clearAction.setEnabled(true);
        tool.addAction(clearAction);
    }

    /**
     * Run the full classification pipeline.
     */
    private void runClassification() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "No Program",
                    "Open a program first.");
            return;
        }

        // Warn if no memory map loaded
        if (memoryMap.isEmpty()) {
            Msg.showWarn(this, tool.getToolFrame(), "No Memory Map",
                    "No SVD or JSON memory map loaded. Using heuristic Cortex-M map. " +
                    "Results will have LOW confidence. Load an SVD file for accurate classification.");
        }

        RegimeAnalysisTask task = new RegimeAnalysisTask(
                currentProgram, memoryMap, this::onClassificationComplete);
        TaskLauncher.launch(task);
    }

    /**
     * Callback when classification completes.
     */
    private void onClassificationComplete(Map<Address, ClassificationResult> newResults) {
        this.results = newResults;

        // Update visualizations
        listingColorizer.updateClassifications(results, currentProgram);
        listingColorizer.colorizeFunctionGraph(currentProgram, results);
        tableColumnProvider.updateClassifications(results);

        // Show summary
        int r1 = 0, r2 = 0, r3a = 0, prov = 0, unclass = 0;
        for (ClassificationResult r : results.values()) {
            switch (r.getRegime()) {
                case REGIME_1 -> r1++;
                case REGIME_2 -> r2++;
                case REGIME_3A -> r3a++;
                case PROVENANCE_CHECK -> prov++;
                case UNCLASSIFIED -> unclass++;
            }
        }

        Msg.showInfo(this, tool.getToolFrame(), "Classification Complete",
                String.format("Regime 1 (deterministic): %d\n" +
                        "Regime 2 (cooperative): %d\n" +
                        "Regime 3a (adversarial): %d\n" +
                        "Provenance check: %d\n" +
                        "Unclassified: %d\n" +
                        "Total: %d",
                        r1, r2, r3a, prov, unclass, results.size()));
    }

    private void loadSvdFile() {
        GhidraFileChooser chooser = new GhidraFileChooser(tool.getToolFrame());
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        chooser.setTitle("Select SVD File");
        File file = chooser.getSelectedFile();
        chooser.dispose();

        if (file != null) {
            try {
                SvdMemoryMapParser parser = new SvdMemoryMapParser(currentProgram);
                memoryMap = parser.parseSvd(file);
                lastLoadedSvdPath = file.getAbsolutePath();
                Msg.showInfo(this, tool.getToolFrame(), "SVD Loaded",
                        "Loaded " + memoryMap.size() + " memory regions from " + file.getName());
            } catch (Exception e) {
                Msg.showError(this, tool.getToolFrame(), "SVD Parse Error",
                        "Failed to parse SVD: " + e.getMessage());
            }
        }
    }

    private void loadJsonFile() {
        GhidraFileChooser chooser = new GhidraFileChooser(tool.getToolFrame());
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        chooser.setTitle("Select JSON Memory Map");
        File file = chooser.getSelectedFile();
        chooser.dispose();

        if (file != null) {
            try {
                SvdMemoryMapParser parser = new SvdMemoryMapParser(currentProgram);
                memoryMap = parser.parseJson(file);
                lastLoadedSvdPath = file.getAbsolutePath();
                Msg.showInfo(this, tool.getToolFrame(), "JSON Loaded",
                        "Loaded " + memoryMap.size() + " memory regions from " + file.getName());
            } catch (Exception e) {
                Msg.showError(this, tool.getToolFrame(), "JSON Parse Error",
                        "Failed to parse JSON: " + e.getMessage());
            }
        }
    }

    private void generateReport() {
        if (results.isEmpty()) {
            Msg.showWarn(this, tool.getToolFrame(), "No Results",
                    "Run classification first.");
            return;
        }

        GhidraFileChooser chooser = new GhidraFileChooser(tool.getToolFrame());
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
        chooser.setTitle("Save Report");
        File file = chooser.getSelectedFile();
        chooser.dispose();

        if (file != null) {
            try {
                RegimeReportGenerator generator = new RegimeReportGenerator();
                generator.generateReport(currentProgram, results, memoryMap, file);
                Msg.showInfo(this, tool.getToolFrame(), "Report Generated",
                        "Report saved to " + file.getAbsolutePath());
            } catch (Exception e) {
                Msg.showError(this, tool.getToolFrame(), "Report Error",
                        "Failed to generate report: " + e.getMessage());
            }
        }
    }

    private void clearClassifications() {
        results.clear();
        listingColorizer.updateClassifications(results, currentProgram);
        tableColumnProvider.updateClassifications(results);
        Msg.showInfo(this, tool.getToolFrame(), "Cleared",
                "All regime classifications removed.");
    }

    private void loadMemoryMapFromProject() {
        // TODO: load from project metadata if previously saved
    }

    private void loadClassificationsFromPropertyMap(Program program) {
        if (program == null) return;
        PropertyMapManager pmgr = program.getUsrPropertyManager();
        @SuppressWarnings("unchecked")
        ObjectPropertyMap<RegimeClassification> map =
            (ObjectPropertyMap<RegimeClassification>)
                pmgr.getObjectPropertyMap(RegimeClassification.PROPERTY_NAME);
        if (map == null) return;

        results.clear();
        AddressIterator it = map.getPropertyIterator();
        while (it.hasNext()) {
            Address addr = it.next();
            RegimeClassification rc = map.get(addr);
            if (rc == null) continue;
            ClassificationResult cr = ClassificationResult.builder()
                .regime(rc.getRegime())
                .confidence(rc.getConfidence())
                .rationale(rc.getClassificationRationale())
                .provenanceCheckScore(rc.getProvenanceCheckScore())
                .build();
            results.put(addr, cr);
        }

        if (!results.isEmpty()) {
            listingColorizer.updateClassifications(results, program);
            tableColumnProvider.updateClassifications(results);
            Msg.info(this, "Loaded " + results.size() + " persisted regime classifications");
        }
    }

    public ClassificationResult getClassification(Address functionEntry) {
        return results.get(functionEntry);
    }

    public Map<Address, ClassificationResult> getAllClassifications() {
        return Collections.unmodifiableMap(results);
    }

    public List<MemoryRegion> getMemoryMap() {
        return Collections.unmodifiableList(memoryMap);
    }
}
