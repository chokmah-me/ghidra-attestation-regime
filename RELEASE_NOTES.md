# Release Notes

## v0.4.0 — 2026-05-12

**Status: Stable** — Inter-procedural taint propagation and computed address range analysis.

### What's New

- **Call-chain taint propagation** — InputSourceTagger now traces CALL opcodes to previously analyzed callees. If a callee reads MMIO or external sources, those sources are propagated to the caller. Enables inter-procedural regime escalation within a single analysis pass.
- **Computed address range analysis** — classifyComputedAccess() no longer conservatively returns Regime 3a for all computed LOADs. New resolveConstantAddress() helper walks Varnode def-use chains (INT_ADD, PTRADD, PTRSUB) up to depth 4 to resolve constant-folded addresses into known memory regions.
- **Incremental taint context** — FunctionRegimeAnalyzer passes the growing priorInputSources map to the tagger as each function is analyzed.

### What's Deferred (v0.5.0 candidates)

- PropertyMapManager persistence — requires Ghidra Saveable API research
- FunctionGraph vertex coloring — requires FunctionGraphService API confirmation

### Tests

79 pure-Java tests passing.

---

## v0.3.0 — 2026-05-12

**Status: Stable** — Full P-code analysis, MarkerService integration, CBRANCH predicate tracing.

### What's New (since v0.2.0)

- **CBRANCH predicate tracing** — ControlFlowAnalyzer now walks SSA for loop predicates and condition checks
- **MarkerService integration** — Colored margin markers in Listing view (green/yellow/red/orange/gray) per regime
- **Complete visualization layer** — RegimeListingColorizer and RegimeTableColumnProvider fully wired

### Tests

79 pure-Java tests passing (added WeightedRegimePropagatorTest coverage).

---

## v0.2.0 — 2026-05-12

**Status: Stable** — Call-graph propagation, visualization layer, report generation.

### What's New (since v0.1.0)

- **WeightedRegimePropagator** — Call-graph propagation with regime-based edge weighting (MAIN_EXECUTION vs CALLBACK_PTR)
- **Visualization layer** — RegimeListingColorizer (MarkerService) and RegimeTableColumnProvider
- **Report generation** — RegimeReportGenerator outputs markdown regime summaries
- **Improved complexity analysis** — Table scanning, pcode operation counting

### Tests

79 pure-Java tests passing.

---

## v0.1.0 — 2026-05-12

**Status: Stable** — 4-step classification pipeline complete. Plugin compiles, installs, and classifies real firmware.

### What's New (since v0.1.0-dev)

- **InputSourceTagger** — Traces data inputs to MMIO/sensor/constant/external via P-code LOAD analysis
- **ControlFlowAnalyzer** — Detects loops (backward jump heuristic), analyzes bounds (P-code SSA constant propagation), tracks volatile MMIO accesses
- **ComplexityAnalyzer** — Fixed cyclomatic complexity counting, implemented heuristic table scanning
- **FunctionRegimeAnalyzer** — Orchestrator wiring all 4 steps; iterates all program functions
- **Headless script** — `ghidra_scripts/AttestationRegimeHeadless.java`, uses orchestrator, prints regime distribution summary
- **Build** — Analysis classes now compiled into plugin JAR (no longer excluded)
- **Tested on real firmware** — STM32F407VG (PlatformIO, 157 KB) imported and analyzed successfully

### What Works

- Install plugin ZIP → run "Classify All Functions" → per-function regime assignments computed
- Headless classification via `analyzeHeadless.bat` + `AttestationRegimeHeadless.java`
- 66 pure-Java tests passing (no Ghidra runtime required)

### What's Not Done

- Step 5 (WeightedRegimePropagator) — call-graph propagation still scaffolded
- Ghidra UI visualization (color-coded Listing, regime report) — still scaffolded
- PropertyMapManager wiring for persistent cross-session storage

### Roadmap to v0.2.0

1. Implement WeightedRegimePropagator (call-graph propagation)
2. Complete RegimeListingColorizer (color-coded functions in Listing view)
3. Complete RegimeReportGenerator (exportable reports)
4. Wire PropertyMapManager for persistent per-project storage
5. Test on additional firmware targets (STM32F1xx, STM32H7xx, RISC-V)

---

## v0.1.0-dev Release Notes

**Status: Prerelease** — Logic validated, Ghidra integration incomplete.

## What's Working

### Core Classification Logic (Production-Grade)
- ✅ **Regime decision tree** — 5-rule priority system (adversarial dominates)
- ✅ **Input source mapping** — Classifies memory regions to regime inputs
- ✅ **Known constant table fingerprinting** — Detects CRC32 IEEE, AES, SHA256, etc.
- ✅ **JSON memory map parser** — Reads STM32F407 and custom peripheral definitions
- ✅ **66 unit and integration tests** — All passing, no Ghidra runtime required

### Testing
- `gradle test` runs 66 tests across 5 test classes
- Pure-Java pipeline tested end-to-end with realistic STM32F407 data
- Decision tree validated against expected regime assignments (UART→3a, ADC→2, timers→1, etc.)

### Documentation
- README updated for Ghidra 12, Windows/PowerShell environment
- CLAUDE.md contains architecture, build instructions, test commands
- Memory map fixture (data/stm32f407_memory_map.json) ready for manual testing

## What's Scaffolded (Requires Ghidra Runtime Integration)

The analysis classes that feed data into the regime decision tree are **excluded from the build**. They need work:

| Class | Purpose | Status |
|-------|---------|--------|
| InputSourceTagger | Trace data inputs to ultimate source (MMIO, sensor, constant, etc.) | Stub, Ghidra-dependent |
| ControlFlowAnalyzer | Detect loop bounds, indirect control flow | Stub, Ghidra-dependent |
| WeightedRegimePropagator | Propagate regimes through call graph (heat map) | Stub, Ghidra-dependent |
| RegimeAnalyzerPlugin | Ghidra UI menu items, background task | Scaffolded |
| RegimeListingColorizer | Color-code functions in Listing view | Scaffolded |
| RegimeReportGenerator | Generate markdown/HTML reports | Scaffolded |

## Installing This Prerelease

```powershell
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.11"
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.4_PUBLIC"
gradle buildExtension
```

The ZIP (`dist/AttestationRegimeClassifier-0.1.0.zip`) will be installable in Ghidra 12, but running "Classify All Functions" will produce incomplete results because the data-gathering (InputSourceTagger, ControlFlowAnalyzer) isn't wired in yet.

## Roadmap to v0.1.0 (Stable)

1. Complete InputSourceTagger — produce InputSource list per function
2. Complete ControlFlowAnalyzer — produce ControlFlowProperties per function
3. Wire all 5 pipeline steps together in a FunctionRegimeAnalyzer task
4. Test on at least one real STM32F407 firmware binary
5. Verify color-coded output and regime distribution make sense
6. Tag as v0.1.0

## Contributing

To help complete the analysis pipeline:
- Each analysis class is heavily TODOed in the source
- All pure-Java logic is tested — focus on Ghidra integration
- The regime decision tree (RegimeAssigner) is production-ready and can be used as a reference for correctness

---

**Release date:** 2026-05-12  
**Author:** Daniyel Yaacov Bilar, Chokmah LLC  
**License:** [Check LICENSE file]
