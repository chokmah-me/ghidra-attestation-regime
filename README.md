# Ghidra Attestation Regime Classifier

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

Output: `dist/AttestationRegimeClassifier-0.4.0.zip`

### Install

**Via Ghidra UI:**
1. File > Install Extensions > Add
2. Select `dist/AttestationRegimeClassifier-0.4.0.zip`
3. Restart Ghidra

**Manual (PowerShell):**
```powershell
Copy-Item dist/AttestationRegimeClassifier-0.4.0.zip `
  $env:GHIDRA_INSTALL_DIR/Ghidra/Extensions/
```

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
Copy-Item dist/AttestationRegimeClassifier-0.4.0.zip `
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
# 79 tests pass, no Ghidra runtime required
```

**Test classes:**
- `AttestationRegimeTest` (13 tests) — regime enum properties, color coding, dominance
- `InputSourceTest` (13 tests) — source type classification and regime inheritance
- `KnownConstantTablesTest` (17 tests) — CRC/AES/SHA table fingerprinting
- `RegimeAssignerTest` (16 tests) — decision tree logic and priority rules
- `IntegrationE2eTest` (7 tests) — end-to-end pipeline with STM32F407 peripherals
- `WeightedRegimePropagatorTest` (13 tests) — call-graph propagation heuristics, weight thresholds

## Current Status (v0.3.0)

**Fully implemented and tested (79 tests):**
- ✅ Regime model and decision tree logic (16 tests)
- ✅ Input source categorization (13 tests)
- ✅ Known constant table identification — CRC32, AES, SHA (17 tests)
- ✅ JSON memory map parser, STM32F407 fixture included (7 integration tests)
- ✅ InputSourceTagger — traces data flows to MMIO/sensor/constant/external sources
- ✅ ControlFlowAnalyzer — CBRANCH predicate tracing (isExternallyDerived SSA walk), hasFunctionPointerUsage detection, loop bounds, indirect control flow, volatile accesses
- ✅ ComplexityAnalyzer — cyclomatic complexity, table scanning, P-code op count
- ✅ FunctionRegimeAnalyzer — 4-step pipeline orchestrator, all functions, progress tracking
- ✅ WeightedRegimePropagator — call-graph propagation with improved regime-based classification (13 tests)
- ✅ RegimeAnalyzerPlugin — Ghidra UI menu integration, MarkerService wiring
- ✅ RegimeAnalysisTask — background task launcher
- ✅ RegimeListingColorizer — MarkerService integration; colored margin markers per regime in Listing view
- ✅ RegimeTableColumnProvider — regime column for Function Table
- ✅ RegimeReportGenerator — markdown classification report output
- ✅ Headless script — `ghidra_scripts/AttestationRegimeHeadless.java`
- ✅ Plugin ZIP installable in Ghidra 12, all classes compiled

**Deferred to v0.4.0:**
- PropertyMapManager persistence (requires RegimeClassification to implement Saveable interface)
- InputSourceTagger computed-access range analysis (needs alias analysis)
- Call-chain taint propagation (interprocedural analysis)
- FunctionGraph node coloring (needs FunctionGraphService integration)

## Sample Memory Maps

- `data/stm32f407_memory_map.json` - STM32F407VG (OpenPLC runtime target)
  Full peripheral map with regime annotations: UART/Ethernet -> Regime 3a,
  ADC -> Regime 2, timers/GPIO/internal -> Regime 1.

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

## References

- Bilar (2026). Three Regimes of Capability Attestation. Zenodo 20114610.
- Bilar (2026). The Computability Filter. Zenodo 19818321.
- Bilar (2026). Shibboleth Lattice Simulation. Zenodo 20090834.
- Bilar (2026). Volt Typhoon as nth-Order Bleeding. Zenodo 19739954.

Daniyel Yaacov Bilar, Chokmah LLC, Vermont.
