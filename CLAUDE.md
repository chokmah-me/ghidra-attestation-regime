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

# Run tests (78 tests, no Ghidra runtime required)
gradle test

# Build the plugin extension
gradle buildExtension

# Output: dist/AttestationRegimeClassifier-0.8.1.zip
```

## Install

**Via install script:**
```powershell
.\scripts\Install-AttestationRegimePlugin.ps1 `
  -GhidraInstallDir "C:\Tools\ghidra_12.0.4_PUBLIC" `
  -PluginZip "dist\AttestationRegimeClassifier-0.8.1.zip"
```

Then in Ghidra: File > Install Extensions > check "Attestation Regime Classifier" > OK > restart.
Then in CodeBrowser: File > Configure > enable RegimeAnalyzerPlugin.

## Architecture

The plugin runs a **5-step classification pipeline** on every function:

1. **InputSourceTagger** — Traces data inputs to their ultimate source (MMIO, sensor, constant, etc.) — ⚠️ Computed-access range analysis deferred
2. **ControlFlowAnalyzer** — CBRANCH predicate tracing (SSA walk for volatile inputs), hasFunctionPointerUsage detection, loop bounds, indirect branches — ✅ Implemented
3. **ComplexityAnalyzer** — Computes cyclomatic complexity, table sizes, pcode operation counts — ✅ Working
4. **RegimeAssigner** — Decision tree assigns Regime 1/2/3a/Provenance/Unclassified — ✅ Production-grade, fully tested
5. **WeightedRegimePropagator** — Propagates regimes through the call graph with heuristic edge weights — ✅ Implemented

Results are cached for Listing view with MarkerService integration (green margin markers = Regime 1, yellow = Regime 2, red = Regime 3a, orange = provenance check, gray = unclassified).

**Current Build Status (v0.8.1):**
- ✅ Pure-Java model & decision tree: 107 tests passing (added MemoryRegionTest: 10 tests, FIELDBUS SourceType)
- ✅ JSON memory map parser: reads STM32F407 fixture and S7 I/O memory map
- ✅ Call-graph propagation with improved regime-based classification
- ✅ ControlFlowAnalyzer: CBRANCH predicate tracing, hasFunctionPointerUsage detection
- ✅ Plugin classes, UI menu integration, report generator: all compiled and included in ZIP
- ✅ MarkerService wiring: colored margin markers in Listing view per regime
- ✅ InputSourceTagger: call-chain taint propagation (CALL opcode inter-procedural tracing)
- ✅ InputSourceTagger: computed address range analysis (Varnode def-use chain constant folding, depth 4)
- ✅ FunctionGraph coloring: vertex background colors per regime (via FunctionGraphPlugin)
- ✅ Headless analysis script: Step 5 propagation + memory map argument support
- ✅ PropertyMapManager persistence: RegimeClassification implements Saveable; classifications survive Ghidra restart
- ✅ FIELDBUS SourceType: industrial field bus support (Profibus, EtherNet/IP, Modbus) for PLC analysis
- ✅ Ghidra 12.x extension loading: extension.properties, Module.manifest, jackson deps in lib/
- ✅ Tools > Attestation Regime menu in CodeBrowser (requires File > Configure to enable)
- ✅ Install script: scripts/Install-AttestationRegimePlugin.ps1
- ✅ Confirmed end-to-end on zephyr-hello_world_stm32f4.elf: 170 functions (17 R1, 143 R3a, 10 Provenance)

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

Two equivalent schemas are supported:

**Option A (start/end bounds):**
```json
{
  "regions": [
    {
      "name": "UART1",
      "start": "0x40011000",
      "end": "0x40011FFF",
      "regime": "REGIME_3A",
      "volatile": true
    }
  ]
}
```

**Option B (baseAddress/size):**
```json
{
  "regions": [
    {
      "name": "UART1",
      "baseAddress": "0x40011000",
      "size": 4096,
      "regime": "REGIME_3A",
      "volatile": true
    }
  ]
}
```

Example: `data/stm32f407_memory_map.json` (STM32F407VG OpenPLC target) — uses start/end format.

## Testing

```powershell
# Run all 97 tests (pure Java, no Ghidra runtime required)
gradle test

# Run specific test classes
gradle test --tests chokmah.plugin.attestation.model.AttestationRegimeTest
gradle test --tests chokmah.plugin.attestation.model.InputSourceTest
gradle test --tests chokmah.plugin.attestation.model.KnownConstantTablesTest
gradle test --tests chokmah.plugin.attestation.model.RegimeClassificationSaveableTest
gradle test --tests chokmah.plugin.attestation.analysis.RegimeAssignerTest
gradle test --tests chokmah.plugin.attestation.analysis.WeightedRegimePropagatorTest
gradle test --tests chokmah.plugin.attestation.IntegrationE2eTest

# View HTML test report
start build/reports/tests/test/index.html
```

**Test Coverage (9 classes, 107 tests):**
- AttestationRegimeTest (13) — regime enum properties, color coding, dominance
- InputSourceTest (14) — source type mapping, regime inheritance, FIELDBUS SourceType
- KnownConstantTablesTest (17) — CRC/AES/SHA fingerprinting
- RegimeAssignerTest (16) — decision tree logic, priority rules
- WeightedRegimePropagatorTest (12) — call-graph propagation weight formulas, thresholds, heuristics
- RegimeClassificationSaveableTest (20) — Saveable impl schema, field contract, serialization schema
- MemoryRegionTest (10) — toInputSourceType() mapping, FIELDBUS peripheral classification
- IntegrationE2eTest (6) — end-to-end pipeline with realistic STM32F407 data

**What's tested:** Pure-Java model, parser, decision tree, propagator heuristics. **What's not tested:** The Ghidra-dependent analyzer classes (InputSourceTagger, ControlFlowAnalyzer, ComplexityAnalyzer) require live Ghidra runtime; full test coverage deferred.

## Firmware Test Collection

Real firmware ELF binaries for testing and validation:

- **Location:** `data/firmware/`
- **Download:** `scripts/fetch_firmware.ps1` downloads 9 pre-built ARM ELF files from Antmicro CDN (~9 MB)
- **Manifest:** `data/firmware/manifest.json` catalogs each binary with expected regime distribution
- **Headless analysis:** `scripts/run_firmware_analysis.ps1` batch-classifies all ELFs via Ghidra
- **Test corpus:** Zephyr, RIOT, Tock, STM32CubeMX firmware; diverse peripheral patterns

See `data/firmware/README.md` for usage details.

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
5. **InputSourceTagger range analysis and call-chain taint** are now in v0.4.0. Varnode def-use chain constant folding (depth 4) resolves computed addresses; CALL opcode handling propagates external sources to callers. ControlFlowAnalyzer CBRANCH predicate tracing is implemented (isExternallyDerived SSA walk).
6. **Industrial field bus support (v0.8.0)** — `InputSource.SourceType.FIELDBUS` classifies reads from Profibus, EtherNet/IP, Modbus, and other ICS-specific buses as Regime 3a. Enables analysis of PLC firmware when a processor module (e.g., s7-ghidra) loads S7 object code. See `data/siemens_s7_io_memory_map.json` for S7 example.

## PLC and Industrial Control System Support

The classifier can analyze firmware from PLCs (Siemens S7, Beckhoff, Allen-Bradley) and other embedded systems beyond ARM Cortex-M:

**Architecture flexibility:**
- **Target:** Any architecture Ghidra supports (ARM Cortex-M, x86, x86-64, MIPS, RISC-V, custom S7 bytecode via processor module)
- **Limitation:** Only ARM Cortex-M has a built-in heuristic memory map. Other architectures require a custom memory map JSON file
- **Critical:** A Ghidra processor module must first load and disassemble/decompile the binary. The classifier operates on Ghidra's P-code (architecture-neutral IR), not raw assembly

**Example: Siemens S7-300/400 PLC**

Use case (Stuxnet-relevant): analyzing PLC firmware that controls critical processes (centrifuge drives, SCADA, power grids).

Steps:
1. Install Ghidra s7-ghidra processor module (community, not official)
2. Load S7 firmware .bin or .s7p file in Ghidra
3. Run auto-analysis with s7-ghidra processor active
4. Provide memory map: `data/siemens_s7_io_memory_map.json` (or your own annotated variant)
5. Run Classify All Functions — Profibus reads/writes will be flagged as FIELDBUS → Regime 3a
6. Taint propagates: any function reading from Profibus-fed data becomes Regime 3a

**New SourceType: FIELDBUS**

- Maps: `MemoryRegion.PeripheralClass.FIELDBUS` → `InputSource.SourceType.FIELDBUS` → `AttestationRegime.REGIME_3A`
- Covers: Profibus DP/PA, EtherNet/IP, Modbus TCP/RTU, CANopen, other industrial buses
- Rationale: ICS buses are network-like (Regime 3a: adversarial input dominance) but distinct from point-to-point comms (UART, Ethernet)
- Regime: 3a (white-box analysis only)

**Memory map format (same as ARM):**

See `data/siemens_s7_io_memory_map.json` for a documented example. The JSON format is architecture-agnostic; addresses are canonical within the binary's address space.

## Gradle Notes

- **GHIDRA_INSTALL_DIR** is read from `System.getenv()` or defaults to `/opt/ghidra`
- **buildExtension** task creates a ZIP with plugin JAR, resources, and data files
- Dependencies are compiled against Ghidra JARs (not shipped in the plugin)

## References

- Bilar (2026) *Three Regimes of Capability Attestation for Autonomous Agents* (Zenodo 20114610)
- Bilar (2026) *The Computability Filter* (Zenodo 19818321)
- Bilar (2026) *Shibboleth Lattice Simulation* (Zenodo 20090834)
