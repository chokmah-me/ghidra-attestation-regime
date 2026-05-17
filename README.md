# Ghidra Attestation Regime Classifier

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![v0.9.0](https://img.shields.io/badge/version-0.9.0-blue.svg)](#)

Computability-bounded firmware triage. Classifies every function in an
embedded firmware image into one of three attestation regimes derived from
Bilar (2026), "Three Regimes of Capability Attestation for Autonomous
Agents" (Zenodo 20114610, OSF axmku). The regimes determine the ceiling
on what any verification/audit method can achieve for that function,
before a single analyst-hour is spent.

This is the Computability Filter (Bilar 2026, Zenodo 19818321) instantiated
as a binary triage tool for ICS/embedded firmware.

Cross-Pollination H: Capability Attestation <-> Computability Filter <->
Shibboleth Lattice <-> AOM.

## The Three Regimes

| Regime | Color | Label | Ceiling |
|--------|-------|-------|---------|
| Regime 1 | Green | Deterministic, Bounded | Formally verifiable (CBMC, Frama-C, Coq) |
| Regime 2 | Yellow | Cooperative Stochastic | Statistical testing (Chernoff bounds) |
| Regime 3a | Red | Adversarial Input Exposure | White-box analysis only |
| Provenance Check | Orange | Unexplained constant tables | Human verification required |
| Unclassified | Gray | Insufficient data | Needs memory map annotation |

Key: Regime 3 checks come BEFORE Regime 2. Adversarial input dominates.

## Quick Start

### Prerequisites

- **Ghidra 12.x** (tested with 12.0.4)
- **JDK 21+** (tested with jdk-21.0.11)
- **Gradle 8+**
- **Windows 11** with PowerShell 7+

### Build

```powershell
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.11"
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.4_PUBLIC"
gradle buildExtension
```

Output: `dist/AttestationRegimeClassifier-0.9.0.zip`

### Install

**Via install script (recommended):**
```powershell
.\scripts\Install-AttestationRegimePlugin.ps1 `
  -GhidraInstallDir "C:\Tools\ghidra_12.0.4_PUBLIC" `
  -PluginZip "dist\AttestationRegimeClassifier-0.9.0.zip"
```

The script stops Ghidra, removes any prior installation, extracts the ZIP, and verifies `extension.properties` is present.

**After the script, two manual steps in Ghidra are required:**
1. Open Ghidra > **File > Install Extensions** > check "Attestation Regime Classifier" > OK > restart Ghidra
2. Open a binary in CodeBrowser > **File > Configure** > find RegimeAnalyzerPlugin > enable it

**Via Ghidra UI only:**
1. File > Install Extensions > Add
2. Select `dist/AttestationRegimeClassifier-0.9.0.zip`
3. Check "Attestation Regime Classifier" in the list > OK > restart Ghidra
4. Open a binary in CodeBrowser > File > Configure > enable RegimeAnalyzerPlugin

### Usage

1. Import firmware binary, run auto-analysis
2. **Mark MMIO regions as volatile** in Ghidra's datatype manager
   (critical: decompiler may fold volatile accesses into constants)
3. Load SVD file or JSON memory map:
   - Tools > Attestation Regime > Load SVD File...
   - Or Load JSON Memory Map... (see `data/stm32f407_memory_map.json`)
4. Tools > Attestation Regime > Classify All Functions
5. Review color-coded Listing and Function Graph
6. Tools > Attestation Regime > Generate Report...

### Headless Testing (no Ghidra UI required)

Install plugin first, then run via `analyzeHeadless`:

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.4_PUBLIC"

# Install plugin
Copy-Item dist/AttestationRegimeClassifier-0.9.0.zip `
  "$env:GHIDRA_INSTALL_DIR/Ghidra/Extensions/"

# Run classification headless
& "$env:GHIDRA_INSTALL_DIR/support/analyzeHeadless.bat" . ProjectName `
  -import path\to\firmware.elf `
  -postScript AttestationRegimeHeadless.java data\stm32f407_memory_map.json `
  -scriptPath ghidra_scripts `
  -deleteProject
```

Output: regime distribution table (Regime 1/2/3a counts, confidence, rationale per function).

## Tests

```powershell
gradle test
# 108 tests pass, no Ghidra runtime required
```

**Test classes:**
- `AttestationRegimeTest` (13 tests) — regime enum properties, color coding, dominance
- `InputSourceTest` (14 tests) — source type classification, regime inheritance, FIELDBUS SourceType
- `KnownConstantTablesTest` (17 tests) — CRC/AES/SHA table fingerprinting
- `RegimeAssignerTest` (16 tests) — decision tree logic and priority rules
- `WeightedRegimePropagatorTest` (12 tests) — call-graph propagation heuristics, weight thresholds
- `RegimeClassificationSaveableTest` (20 tests) — Saveable schema, field ordering, serialization contract
- `MemoryRegionTest` (10 tests) — toInputSourceType() mapping for all region/peripheral types including FIELDBUS
- `IntegrationE2eTest` (6 tests) — end-to-end pipeline with STM32F407 peripherals

## Current Status (v0.9.0)

**Fully implemented and tested (108 tests):**
- ✅ Regime model and decision tree logic (16 tests)
- ✅ Input source categorization (13 tests)
- ✅ Known constant table identification — CRC32, AES, SHA (17 tests)
- ✅ JSON memory map parser, STM32F407 fixture included (7 integration tests)
- ✅ InputSourceTagger — traces data flows to MMIO/sensor/constant/external sources; call-chain taint propagation; computed address range analysis (Varnode def-use constant folding, depth 4)
- ✅ ControlFlowAnalyzer — CBRANCH predicate tracing (isExternallyDerived SSA walk), hasFunctionPointerUsage detection, loop bounds, indirect control flow, volatile accesses
- ✅ ComplexityAnalyzer — cyclomatic complexity, table scanning, P-code op count
- ✅ FunctionRegimeAnalyzer — 4-step pipeline orchestrator, all functions, progress tracking
- ✅ WeightedRegimePropagator — call-graph propagation with improved regime-based classification (12 tests)
- ✅ RegimeAnalyzerPlugin — Ghidra UI menu integration, MarkerService wiring
- ✅ RegimeAnalysisTask — background task launcher
- ✅ RegimeListingColorizer — MarkerService integration; colored margin markers per regime in Listing view
- ✅ RegimeTableColumnProvider — regime column for Function Table
- ✅ RegimeReportGenerator — markdown classification report output
- ✅ Plugin ZIP installable in Ghidra 12, all classes compiled

**v0.4.0 additions:**
- ✅ InputSourceTagger computed address range analysis (Varnode def-use chain, depth 4)
- ✅ Call-chain taint propagation (CALL opcode interprocedural tracing)
- ✅ MarkerService wiring (green/yellow/red/orange/gray margin markers)

**Post-v0.4.0 additions (Firmware Test Infrastructure):**
- ✅ 9 pre-built ARM ELF firmware test corpus (Antmicro CDN / Renode suite)
- ✅ Headless analysis pipeline (`scripts/fetch_firmware.ps1`, `scripts/run_firmware_analysis.ps1`)
- ✅ PlatformIO project configs for STM32F407 examples (ADC, GPIO EXTI, Timer)

**v0.5.0 additions:**
- ✅ FunctionGraph vertex coloring — regime colors (green/yellow/red/orange/gray) applied to graph vertices via FunctionGraphPlugin
- ✅ AttestationRegimeHeadless.java — Step 5 weighted propagation, memory map argument, JSON output support

**v0.6.0 additions:**
- ✅ PropertyMap persistence: regime classifications survive program close and Ghidra restart
- ✅ RegimeClassification implements Saveable + ExtensionPoint (schema version 1)
- ✅ Serializes regime, confidence, provenance score, and rationale per function
- ✅ programOpened / programClosed lifecycle hooks in RegimeAnalyzerPlugin
- ✅ Classifications auto-load from PropertyMap on program open; visualizations updated automatically

**v0.7.0 additions:**
- ✅ RegimeClassificationSaveableTest: 20 unit tests for Saveable implementation
- ✅ Tests cover schema version, field ordering, serialization contract, all enum values
- ✅ Tests validate confidence levels, provenanceCheckScore, and rationale persistence
- ✅ Total test suite: 97 tests (pure Java, no Ghidra runtime required)

**v0.8.0 additions:**
- ✅ FIELDBUS SourceType: industrial field bus support (Profibus, EtherNet/IP, Modbus) -> Regime 3a
- ✅ MemoryRegionTest: 10 tests covering toInputSourceType() for all peripheral classes
- ✅ siemens_s7_io_memory_map.json: S7-300/400 PLC I/O memory map with Profibus as FIELDBUS
- ✅ Total test suite: 107 tests (pure Java, no Ghidra runtime required)

**v0.8.1 additions (build system / Ghidra 12.x compatibility):**
- ✅ `extension.properties` — renamed from `plugin.properties`; Ghidra 12.x requires this exact filename
- ✅ `Module.manifest` — added required module marker file; without it Ghidra's module loader skips the extension
- ✅ Jackson deps bundled in `lib/` — `copyDependencies` Gradle task added; `jackson-databind`, `jackson-core`, `jackson-annotations` now shipped in ZIP
- ✅ JAR placed in `lib/` subdirectory — Ghidra ClassSearcher scans `lib/`, not the extension root
- ✅ Menu path corrected — all actions moved to `Tools > Attestation Regime` (was standalone top-level menu)
- ✅ Install script — `scripts/Install-AttestationRegimePlugin.ps1` automates stop/remove/extract/verify
- ✅ First confirmed working end-to-end Ghidra 12.0.4 UI install: 170 functions classified on `zephyr-hello_world_stm32f4.elf`

**v0.9.0 additions:**
- ✅ Memory map persistence — last-used JSON/SVD path saved to tool Options; auto-reloads on next `programOpened`, no manual re-selection after restart
- ✅ SVD peripheral size — `computePeripheralSize()` now reads register offsets from SVD XML and rounds up to next power of two (min 1KB); was always returning 4KB
- ✅ MemoryRegion null-safety — constructor accepts null start/end addresses; fixes 10 `MemoryRegionTest` tests broken since v0.8.0 (AddressRangeImpl rejects null)
- ✅ 108 tests passing

## Sample Memory Maps

- `data/stm32f407_memory_map.json` - STM32F407VG (OpenPLC runtime target)
  Full peripheral map with regime annotations: UART/Ethernet -> Regime 3a,
  ADC -> Regime 2, timers/GPIO/internal -> Regime 1.
- `data/siemens_s7_io_memory_map.json` - Siemens S7-300/400 PLC I/O address space
  Profibus master module tagged as FIELDBUS (Regime 3a). Template for ICS PLC analysis.
  Requires a Ghidra S7 processor module to load S7 object code before classification.

## Architecture

### 5-Step Pipeline

```
Step 1: InputSourceTagger      -> trace data inputs to ultimate source
Step 2: ControlFlowAnalyzer    -> loop bounds, indirect CF detection
Step 3: ComplexityAnalyzer     -> cyclomatic, table size, pcode ops
Step 4: RegimeAssigner         -> priority decision tree
Step 5: WeightedRegimePropagator -> call-graph propagation (heat map)
```

### Key Limitations (Stated Upfront)

1. **Regime 3b is a flag, not an automated classifier.** PRF-embeddability
detection produces too many false positives. CRC tables and backdoor
triggers look identical. The plugin flags; the analyst decides.

2. **Requires memory map annotation.** Without SVD or manual peripheral
address mapping, the classifier defaults most external accesses to
Regime 3a (conservative but uninformative). This is a mid-analysis tool,
not a first-pass tool.

3. **Regime propagation in monolithic images classifies almost everything
as Regime 3.** This is correct: it demonstrates quantitatively why
monolithic firmware architectures are unauditable and why hardware
isolation (MPU partitioning) is necessary.

4. **Alias analysis on stripped firmware is imprecise.** Over-approximation
is acceptable (safe for security). ICS firmware mitigates this:
predominantly global variables and MMIO registers, dynamic allocation
often forbidden (MISRA C prohibits malloc).

5. **No person-hour estimates.** The relationship between complexity
metrics and actual verification effort is empirically weak. Report
regime classification and function counts, not time estimates.

## Prototype Target

OpenPLC runtime on STM32 is FOSS firmware with:
- Known memory map (STM32 SVD available)
- Modbus TCP handler (Regime 3a)
- PLC scan cycle logic (Regime 1/2 mix)
- Sensor input processing (Regime 2)
- Simple enough to manually verify classifier output

## Publication

Title direction: "Computability-Bounded Firmware Triage: Attestation
Regime Classification for Embedded Safety Systems"

Venue: USENIX Security, CCS, WOOT, or S4x.

## Cite This Work

To cite the AttestationRegimeClassifier plugin:

```bibtex
@software{bilar2026attestationregimeclassifier,
  title   = {AttestationRegimeClassifier -- Ghidra Plugin for ICS/Embedded Firmware Attestation Regime Classification},
  author  = {Bilar, Daniyel Yaacov},
  year    = {2026},
  version = {0.9.0},
  url     = {https://github.com/chokmah/ghidra-attestation-regime}
}
```

See [CITATION.cff](CITATION.cff) for standard citation metadata.

## References

- Bilar (2026). Three Regimes of Capability Attestation. Zenodo 20114610.
- Bilar (2026). The Computability Filter. Zenodo 19818321.
- Bilar (2026). Shibboleth Lattice Simulation. Zenodo 20090834.
- Bilar (2026). Volt Typhoon as nth-Order Bleeding. Zenodo 19739954.

---

**License:** MIT — see [LICENSE](LICENSE)

Daniyel Yaacov Bilar, Chokmah LLC, Vermont.
