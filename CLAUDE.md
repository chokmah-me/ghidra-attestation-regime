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

- **Ghidra 12.x** (tested with 12.0.4)
- **JDK 21+** (tested with jdk-21.0.11)
- **Gradle 8+** (check with `gradle -v`)
- **Windows 11** with PowerShell 7+
- **GHIDRA_INSTALL_DIR** and **JAVA_HOME** environment variables (set per-session in PowerShell)

## Build & Test

```powershell
# Set environment variables (per-session)
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.11"
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.4_PUBLIC"

# Run tests (66 tests, no Ghidra runtime required)
gradle test

# Build the plugin extension
gradle buildExtension

# Output: dist/AttestationRegimeClassifier-0.1.0.zip
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

1. **InputSourceTagger** — Traces data inputs to their ultimate source (MMIO, sensor, constant, etc.) — **SCAFFOLDED**
2. **ControlFlowAnalyzer** — Detects loop bounds, recursion, indirect branches — **SCAFFOLDED**
3. **ComplexityAnalyzer** — Computes cyclomatic complexity, table sizes, pcode operation counts — ✅ Working
4. **RegimeAssigner** — Decision tree assigns Regime 1/2/3a/Provenance/Unclassified — ✅ Production-grade, fully tested
5. **WeightedRegimePropagator** — Propagates regimes through the call graph — **SCAFFOLDED**

Results are color-coded in the Listing view (green = Regime 1, yellow = Regime 2, red = Regime 3a, orange = provenance check, gray = unclassified).

**Current Build Status:**
- ✅ Pure-Java model & decision tree: 66 tests passing
- ✅ JSON memory map parser: reads STM32F407 fixture
- ⚠️ Analysis classes (steps 1, 2, 5): excluded from build, require Ghidra runtime
- ⚠️ Visualization & reporting: scaffolded

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
# Run all 66 tests (pure Java, no Ghidra runtime required)
gradle test

# Run specific test classes
gradle test --tests chokmah.plugin.attestation.model.AttestationRegimeTest
gradle test --tests chokmah.plugin.attestation.model.KnownConstantTablesTest
gradle test --tests chokmah.plugin.attestation.model.InputSourceTest
gradle test --tests chokmah.plugin.attestation.analysis.RegimeAssignerTest
gradle test --tests chokmah.plugin.attestation.IntegrationE2eTest

# View HTML test report
start build/reports/tests/test/index.html
```

**Test Coverage (5 classes, 66 tests):**
- AttestationRegimeTest (13) — regime enum properties, color coding, dominance
- InputSourceTest (13) — source type mapping, regime inheritance
- KnownConstantTablesTest (17) — CRC/AES/SHA fingerprinting
- RegimeAssignerTest (16) — decision tree logic, priority rules
- IntegrationE2eTest (7) — end-to-end pipeline with realistic STM32F407 data

**What's tested:** Pure-Java model, parser, decision tree. **What's not:** The analysis classes (InputSourceTagger, ControlFlowAnalyzer, WeightedRegimePropagator) require live Ghidra runtime and are scaffolded.

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
5. **Analysis classes are scaffolded** — InputSourceTagger and ControlFlowAnalyzer need completion to produce real results in Ghidra UI. See TESTING_ROADMAP.md for next steps.

## Gradle Notes

- **GHIDRA_INSTALL_DIR** is read from `System.getenv()` or defaults to `/opt/ghidra`
- **buildExtension** task creates a ZIP with plugin JAR, resources, and data files
- Dependencies are compiled against Ghidra JARs (not shipped in the plugin)

## References

- Bilar (2026) *Three Regimes of Capability Attestation for Autonomous Agents* (Zenodo 20114610)
- Bilar (2026) *The Computability Filter* (Zenodo 19818321)
- Bilar (2026) *Shibboleth Lattice Simulation* (Zenodo 20090834)
