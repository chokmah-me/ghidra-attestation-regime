// RegimeReportGenerator.java
// Markdown report generator for regime classification results.
//
// For each regime, lists functions, their verification implication,
// and estimated effort where computable:
//   - Regime 1: N functions, amenable to bounded model checking
//   - Regime 2: M functions, statistical testing applicable
//   - Regime 3: K functions, white-box analysis required
//
// Do NOT estimate person-hours. The relationship between complexity
// metrics and verification effort is empirically weak.
//
// Per Limitation 5 (#24, Section 8): Report regime classification and
// function counts, not time estimates.

package chokmah.plugin.attestation.report;

import chokmah.plugin.attestation.model.*;
import chokmah.plugin.attestation.visualization.RegimeListingColorizer;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Generates a Markdown classification report.
 */
public class RegimeReportGenerator {

    private static final String NEWLINE = "\n";

    public void generateReport(Program program,
                               Map<Address, ClassificationResult> results,
                               List<MemoryRegion> memoryMap,
                               File outputFile) throws IOException {

        StringBuilder sb = new StringBuilder();

        // Header
        sb.append("# Attestation Regime Classification Report").append(NEWLINE);
        sb.append(NEWLINE);
        sb.append("**Program:** ").append(program.getName()).append(NEWLINE);
        sb.append("**Architecture:** ").append(program.getLanguage().getProcessor().toString()).append(NEWLINE);
        sb.append("**Date:** ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date())).append(NEWLINE);
        sb.append("**Total Functions:** ").append(results.size()).append(NEWLINE);
        sb.append("**Memory Regions Loaded:** ").append(memoryMap.size()).append(NEWLINE);
        sb.append(NEWLINE);
        sb.append("---").append(NEWLINE);
        sb.append(NEWLINE);

        // Summary statistics
        appendSummary(sb, results);

        // Memory map section
        appendMemoryMap(sb, memoryMap);

        // Regime sections
        appendRegimeSection(sb, program, results, AttestationRegime.REGIME_3A, "Regime 3a: Adversarial Input Exposure");
        appendRegimeSection(sb, program, results, AttestationRegime.PROVENANCE_CHECK, "Provenance Check: Unexplained Constant Tables");
        appendRegimeSection(sb, program, results, AttestationRegime.REGIME_2, "Regime 2: Cooperative Stochastic");
        appendRegimeSection(sb, program, results, AttestationRegime.REGIME_1, "Regime 1: Deterministic, Bounded");
        appendRegimeSection(sb, program, results, AttestationRegime.UNCLASSIFIED, "Unclassified");

        // Footer / references
        appendReferences(sb);

        // Write file
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             OutputStreamWriter writer = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
            writer.write(sb.toString());
        }
    }

    private void appendSummary(StringBuilder sb, Map<Address, ClassificationResult> results) {
        int r1 = 0, r2 = 0, r3a = 0, prov = 0, unclass = 0;
        double totalPcodeOps = 0;

        for (ClassificationResult r : results.values()) {
            totalPcodeOps += r.getPcodeOpCount();
            switch (r.getRegime()) {
                case REGIME_1 -> r1++;
                case REGIME_2 -> r2++;
                case REGIME_3A -> r3a++;
                case PROVENANCE_CHECK -> prov++;
                case UNCLASSIFIED -> unclass++;
            }
        }

        int total = results.size();
        sb.append("## Summary").append(NEWLINE);
        sb.append(NEWLINE);

        sb.append("| Regime | Count | Percentage | Verification Implication |").append(NEWLINE);
        sb.append("|--------|-------|------------|--------------------------|").append(NEWLINE);

        appendRegimeRow(sb, AttestationRegime.REGIME_3A, r3a, total);
        appendRegimeRow(sb, AttestationRegime.PROVENANCE_CHECK, prov, total);
        appendRegimeRow(sb, AttestationRegime.REGIME_2, r2, total);
        appendRegimeRow(sb, AttestationRegime.REGIME_1, r1, total);
        appendRegimeRow(sb, AttestationRegime.UNCLASSIFIED, unclass, total);

        sb.append(NEWLINE);
        sb.append("**Key insight:** ").append(r3a + prov).append(" functions (")
                .append(String.format("%.1f%%", 100.0 * (r3a + prov) / Math.max(total, 1)))
                .append(") require white-box analysis or provenance verification. ");
        sb.append("These are the functions where statistical testing (fuzzing, ");
        sb.append("Chernoff-bound sampling) is insufficient regardless of sample size.");
        sb.append(NEWLINE);
        sb.append(NEWLINE);

        // Category error callout
        if (r3a > 0 && r2 > 0) {
            sb.append("> **Category Error Alert:** Regime 2 methods (statistical testing, ");
            sb.append("fuzzing) are being applied to ").append(r3a);
            sb.append(" functions that process adversarial input. ");
            sb.append("The Chernoff bound does not hold when the agent is adversarial ");
            sb.append("(#24, #23). The same error appears in LLM evaluation ");
            sb.append("(n_obs ~ 34 applied to Regime 3 peer-preservation).");
            sb.append(NEWLINE);
            sb.append(NEWLINE);
        }

        // Monolithic firmware warning
        if ((r3a + prov) > total * 0.7) {
            sb.append("> **Monolithic Firmware Warning:** >70% of functions classified ");
            sb.append("as Regime 3. This is correct for monolithic firmware without ");
            sb.append("hardware isolation (MPU/TrustZone partitioning). Regime propagation ");
            sb.append("flows through all call edges because there are no isolation ");
            sb.append("boundaries. This demonstrates quantitatively why monolithic ");
            sb.append("architectures are unauditable.");
            sb.append(NEWLINE);
            sb.append(NEWLINE);
        }

        sb.append("---").append(NEWLINE);
        sb.append(NEWLINE);
    }

    private void appendRegimeRow(StringBuilder sb, AttestationRegime regime, int count, int total) {
        String color = RegimeListingColorizer.getHtmlColorForRegime(regime);
        sb.append(String.format("| <span style=\"color:%s\">%s</span> | %d | %.1f%% | %s |",
                color, regime.getLabel(), count,
                100.0 * count / Math.max(total, 1),
                regime.getVerificationImplication()));
        sb.append(NEWLINE);
    }

    private void appendMemoryMap(StringBuilder sb, List<MemoryRegion> memoryMap) {
        sb.append("## Memory Map").append(NEWLINE);
        sb.append(NEWLINE);

        if (memoryMap.isEmpty()) {
            sb.append("*No SVD or JSON memory map loaded. Used heuristic Cortex-M map.*");
            sb.append(NEWLINE);
        } else {
            sb.append("| Region | Address Range | Type | Peripheral |").append(NEWLINE);
            sb.append("|--------|--------------|------|------------|").append(NEWLINE);
            for (MemoryRegion region : memoryMap) {
                sb.append(String.format("| %s | 0x%s - 0x%s | %s | %s |",
                        region.getName(),
                        region.getAddressRange().getMinAddress(),
                        region.getAddressRange().getMaxAddress(),
                        region.getRegionType(),
                        region.getPeripheralClass()));
                sb.append(NEWLINE);
            }
        }
        sb.append(NEWLINE);
        sb.append("---").append(NEWLINE);
        sb.append(NEWLINE);
    }

    private void appendRegimeSection(StringBuilder sb, Program program,
                                      Map<Address, ClassificationResult> results,
                                      AttestationRegime filterRegime, String sectionTitle) {
        List<Map.Entry<Address, ClassificationResult>> filtered = results.entrySet().stream()
                .filter(e -> e.getValue().getRegime() == filterRegime)
                .sorted(Comparator.comparing(e -> e.getKey().toString()))
                .toList();

        if (filtered.isEmpty()) {
            return;
        }

        sb.append("## ").append(sectionTitle).append(NEWLINE);
        sb.append(NEWLINE);
        sb.append("**Count:** ").append(filtered.size()).append(" functions").append(NEWLINE);
        sb.append(NEWLINE);

        switch (filterRegime) {
            case REGIME_1 -> {
                sb.append("These functions are candidates for bounded model checking ");
                sb.append("(CBMC, Frama-C/WP, Coq extraction comparison).");
                sb.append(NEWLINE);
            }
            case REGIME_2 -> {
                sb.append("Statistical testing applies. Estimated observation count ");
                sb.append("depends on input dimensionality and branching factor.");
                sb.append(NEWLINE);
            }
            case REGIME_3A -> {
                sb.append("White-box analysis, formal methods, or architectural isolation ");
                sb.append("required. Statistical testing insufficient regardless of sample size.");
                sb.append(NEWLINE);
            }
            case PROVENANCE_CHECK -> {
                sb.append("Table contents must match known standards. Analyst checks whether ");
                sb.append("table matches CRC-32 polynomial, IEEE 754, published thermocouple curves.");
                sb.append(NEWLINE);
            }
            case UNCLASSIFIED -> {
                sb.append("Insufficient memory map data for classification. ");
                sb.append("Load SVD or JSON memory map and re-run.");
                sb.append(NEWLINE);
            }
        }
        sb.append(NEWLINE);

        sb.append("| Function | Address | Confidence | PcodeOps | Complexity | Tables |").append(NEWLINE);
        sb.append("|----------|---------|------------|----------|------------|--------|").append(NEWLINE);

        FunctionManager fm = program.getFunctionManager();
        for (Map.Entry<Address, ClassificationResult> entry : filtered) {
            Address addr = entry.getKey();
            ClassificationResult cr = entry.getValue();
            Function func = fm.getFunctionAt(addr);
            String funcName = func != null ? func.getName() : addr.toString();

            sb.append(String.format("| %s | %s | %s | %d | %d | %d |",
                    funcName, addr,
                    cr.getConfidence(),
                    cr.getPcodeOpCount(),
                    cr.getCyclomaticComplexity(),
                    cr.getLookupTableEntries()));
            sb.append(NEWLINE);
        }

        // Detail section with rationales (collapsed)
        sb.append(NEWLINE);
        sb.append("<details>").append(NEWLINE);
        sb.append("<summary>Rationales (click to expand)</summary>").append(NEWLINE);
        sb.append(NEWLINE);
        for (Map.Entry<Address, ClassificationResult> entry : filtered) {
            Address addr = entry.getKey();
            ClassificationResult cr = entry.getValue();
            Function func = fm.getFunctionAt(addr);
            String funcName = func != null ? func.getName() : addr.toString();

            sb.append("### ").append(funcName).append(" @ ").append(addr).append(NEWLINE);
            sb.append(cr.getRationale()).append(NEWLINE);
            sb.append(NEWLINE);
        }
        sb.append("</details>").append(NEWLINE);
        sb.append(NEWLINE);
        sb.append("---").append(NEWLINE);
        sb.append(NEWLINE);
    }

    private void appendReferences(StringBuilder sb) {
        sb.append("## References").append(NEWLINE);
        sb.append(NEWLINE);
        sb.append("- **#24** Bilar (2026). Three Regimes of Capability Attestation ");
        sb.append("for Autonomous Agents. Zenodo 20114610, OSF axmku.").append(NEWLINE);
        sb.append("- **#2** Bilar (2026). The Computability Filter. Zenodo 19818321.").append(NEWLINE);
        sb.append("- **#23** Bilar (2026). Recognition Channel Dynamics in the Shibboleth ");
        sb.append("Lattice: Simulation Study. Zenodo 20090834, OSF tprvz.").append(NEWLINE);
        sb.append("- **#5** Bilar (2026). Volt Typhoon as nth-Order Bleeding. ");
        sb.append("Zenodo 19739954, OSF autqy.").append(NEWLINE);
        sb.append("- **#14** Golden Dome AOM paper (reference).").append(NEWLINE);
        sb.append("- **#16** Anduril LatticeOS AOM paper (reference).").append(NEWLINE);
        sb.append(NEWLINE);
        sb.append("---").append(NEWLINE);
        sb.append(NEWLINE);
        sb.append("*Generated by Ghidra Attestation Regime Classifier v0.8.1*").append(NEWLINE);
        sb.append("*Cross-Pollination H: Capability Attestation <-> Computability Filter ");
        sb.append("<-> Shibboleth Lattice*").append(NEWLINE);
    }
}
