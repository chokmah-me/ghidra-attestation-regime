# v0.1.0-dev Release Notes

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
