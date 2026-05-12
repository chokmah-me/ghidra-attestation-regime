# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

<!-- session-recall:v1 — DO NOT EDIT MANUALLY -->
## Progressive Session Recall — RUN FIRST ON EVERY PROMPT

**Run `session-recall` FIRST on every prompt before doing anything else.** It costs ~50 tokens and prevents expensive blind searches.

```bash
session-recall files --json --limit 10  # recently touched files
session-recall files --days 7 --json    # files touched in last 7 days
session-recall list --json --limit 5    # recent sessions
session-recall list --days 2 --json     # sessions from last 2 days
session-recall search '<term>' --json   # full-text search
session-recall search '<term>' --days 5 # search last 5 days only
session-recall checkpoints --days 3     # checkpoints from last 3 days
session-recall repos --json             # discovered repositories across providers
session-recall show <id> --json         # drill into one session
session-recall health --json            # 8-dimension health check
session-recall schema-check             # validate DB schema (run after Copilot CLI upgrade)
```

**`--days N` works on all 4 query commands** (`list`, `files`, `checkpoints`, `search`) — filters to sessions/files/checkpoints from the last N days.

Only use filesystem tools (grep, glob, find) if session-recall returns nothing useful.
If `session-recall` errors, continue silently — it's a convenience, not a blocker.
<!-- /session-recall:v1 -->

## Project Overview

**Attestation Regime Classifier** is a Ghidra plugin that analyzes embedded firmware and classifies functions into one of three attestation regimes based on their input sources and control flow properties. Regimes determine the maximum verification guarantee possible for each function (formally provable, statistically testable, or adversarial input exposure only).

This instantiates the Computability Filter (Bilar 2026) as a practical triage tool for ICS/embedded firmware analysis.

## Prerequisites

- **Ghidra 11.x** installed
- **JDK 17+** (check with `java -version`)
- **Gradle 8+** (check with `gradle -v`)
- **GHIDRA_INSTALL_DIR** environment variable set to your Ghidra installation path
  - Example: `$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.0_PUBLIC"`

## Build & Package

```powershell
# Set Ghidra path (one-time setup)
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.4_PUBLIC\"

# Build the plugin extension
gradle buildExtension

# Output is in dist/AttestationRegimeClassifier-0.1.0.zip
```

## Install

Two methods:

**Via Ghidra UI:**
1. Open Ghidra
2. File > Install Extensions > Add
3. Select `dist/AttestationRegimeClassifier-0.1.0.zip`

**Manual:**
```powershell
Copy-Item dist/AttestationRegimeClassifier-0.1.0.zip `
  $env:GHIDRA_INSTALL_DIR/Ghidra/Extensions/
```

Then restart Ghidra.

## Architecture

The plugin runs a **5-step classification pipeline** on every function:

1. **InputSourceTagger** — Traces data inputs to their ultimate source (MMIO, sensor, constant, etc.)
2. **ControlFlowAnalyzer** — Detects loop bounds, recursion, indirect branches
3. **ComplexityAnalyzer** — Computes cyclomatic complexity, table sizes, pcode operation counts
4. **RegimeAssigner** — Decision tree assigns Regime 1/2/3a/Provenance/Unclassified
5. **WeightedRegimePropagator** — Propagates regimes through the call graph

Results are color-coded in the Listing view (green = Regime 1, yellow = Regime 2, red = Regime 3a, orange = provenance check, gray = unclassified).

## Code Structure

```
src/main/java/chokmah/plugin/attestation/
├── RegimeAnalyzerPlugin.java          # Main plugin entry, Ghidra UI actions
├── RegimeAnalysisTask.java            # Background task launcher
├── analysis/                          # Core classification logic
│   ├── InputSourceTagger.java
│   ├── ControlFlowAnalyzer.java
│   ├── ComplexityAnalyzer.java
│   ├── RegimeAssigner.java
│   ├── WeightedRegimePropagator.java
│   └── FunctionRegimeAnalyzer.java
├── model/                             # Data structures
│   ├── AttestationRegime.java         # Enum: REGIME_1/2/3A/PROVENANCE/UNCLASSIFIED
│   ├── ClassificationResult.java      # Per-function result
│   ├── MemoryRegion.java              # Address range + regime hint
│   ├── InputSource.java               # Enum: MMIO, SENSOR, CONSTANT, etc.
│   └── ...
├── visualization/                     # Ghidra UI integration
│   ├── RegimeListingColorizer.java    # Color-codes the Listing view
│   └── RegimeTableColumnProvider.java # Adds regime column to Function Table
├── parser/                            # Memory map loaders
│   └── SvdMemoryMapParser.java        # Parses SVD (CMSIS) or JSON
└── report/
    └── RegimeReportGenerator.java     # Generates markdown reports
```

## Usage Workflow

1. **Import firmware** in Ghidra and run auto-analysis (`Ctrl+E`)
2. **Mark MMIO regions as volatile** in Data Type Manager (critical: decompiler behavior changes)
3. **Load memory map**:
   - Tools > Attestation Regime > Load SVD File... (ARM CMSIS-SVD)
   - Or Tools > Attestation Regime > Load JSON Memory Map...
4. **Classify**: Tools > Attestation Regime > Classify All Functions
5. **Review** color-coded Listing and Function Graph
6. **Report**: Tools > Attestation Regime > Generate Report...

## Memory Map Files

Memory maps are **critical for accuracy**. Without them, the classifier defaults to a heuristic Cortex-M map and produces low-confidence results.

### JSON Format

```json
{
  "regions": [
    {
      "name": "UART1",
      "baseAddress": "0x40011000",
      "size": 4096,
      "regime": "REGIME_3A",
      "volatile": true
    },
    {
      "name": "ADC1",
      "baseAddress": "0x40012000",
      "size": 256,
      "regime": "REGIME_2",
      "volatile": true
    }
  ]
}
```

Example: `data/stm32f407_memory_map.json` (STM32F407VG OpenPLC target)

## Testing

```powershell
# Run unit tests
gradle test

# Run a specific test
gradle test --tests chokmah.plugin.attestation.analysis.ComplexityAnalyzerTest
```

Tests use JUnit 5 (Jupiter).

## Three Regimes (Quick Reference)

| Regime | Color | Meaning | Verification Ceiling |
|--------|-------|---------|----------------------|
| **1** | Green | Deterministic, bounded input/loops | Formal proof (CBMC, Frama-C, Coq) |
| **2** | Yellow | Cooperative stochastic, finite sample space | Statistical testing (Chernoff bounds) |
| **3a** | Red | Adversarial input exposure (external source) | White-box analysis only |
| **Provenance** | Orange | Unexplained constant tables (CRC, lookup) | Manual analyst review |
| **Unclassified** | Gray | Insufficient data (no memory map) | Needs annotation |

**Key:** Regime 3 analysis must come before Regime 2. Adversarial input dominates.

## Key Limitations

1. **Regime 3b (backdoor detection)** is a flag, not automated. PRF-embeddability looks identical to CRC tables.
2. **Requires memory map** for meaningful results. Monolithic firmware classifies as mostly Regime 3 (correct: it's unauditable without partitioning).
3. **Alias analysis** on stripped firmware is imprecise (over-approximation is safe for security).
4. **No person-hour estimates** — complexity does not reliably predict verification effort.

## Gradle Notes

- **GHIDRA_INSTALL_DIR** is read from `System.getenv()` or defaults to `/opt/ghidra`
- **buildExtension** task creates a ZIP with plugin JAR, resources, and data files
- Dependencies are compiled against Ghidra JARs (not shipped in the plugin)

## References

- Bilar (2026) *Three Regimes of Capability Attestation for Autonomous Agents* (Zenodo 20114610)
- Bilar (2026) *The Computability Filter* (Zenodo 19818321)
- Bilar (2026) *Shibboleth Lattice Simulation* (Zenodo 20090834)
