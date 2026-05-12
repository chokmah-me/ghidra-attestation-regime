# Testing Roadmap: Real Firmware

## Current State
- ✅ Pure-Java classification logic (66 tests, all passing)
- ✅ Plugin ZIP builds (`dist/AttestationRegimeClassifier-0.1.0.zip`)
- ⚠️ Ghidra integration scaffolded (InputSourceTagger, ControlFlowAnalyzer, WeightedRegimePropagator not wired)

## What You Can Test Now (Pure Logic)

**Test the regime decision tree without Ghidra:**
```powershell
gradle test --tests IntegrationE2eTest
# 7 tests validate regime assignments with realistic data
# (UART→3a, ADC→2, timers→1, mixed→3a dominates, etc.)
```

This proves the classification logic works. It does **not** require real firmware.

---

## What You Need to Test with Real Firmware

### Phase 1: Get Firmware + Ghidra Running (Today)

**1. Download OpenPLC Runtime (STM32F407 target)**
- https://github.com/thiagoralves/OpenPLC_v3 — pre-built binaries exist
- Or use any STM32F407 firmware (e.g., from STMicroelectronics examples)
- Binary should be a `.elf`, `.bin`, or `.hex` file

**2. Open Ghidra and import the binary**
- File > Import File > select firmware
- Let auto-analysis run (`Ctrl+E`)

**3. (Critical) Mark MMIO as volatile**
- Window > Ghidra Project Window > Data Type Manager
- Find or create ARM Cortex-M MMIO structure (0x40000000+)
- Mark all fields as `volatile`
- This changes decompiler behavior (doesn't fold volatile accesses)

**4. Load the JSON memory map**
- Tools > Attestation Regime > Load JSON Memory Map...
  (if plugin is installed; see "How to Install" below)
- Select `data/stm32f407_memory_map.json`

### Phase 2: Install & Run Plugin (Requires Completing Analysis Classes)

**How to install:**
```powershell
# Build the plugin
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.11"
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.4_PUBLIC"
gradle buildExtension

# Install via UI:
# File > Install Extensions > Add > dist/AttestationRegimeClassifier-0.1.0.zip
# Restart Ghidra
```

**Run classification:**
```
Tools > Attestation Regime > Classify All Functions
```

**BUT:** This will **not produce results yet** because:
- InputSourceTagger is a stub (doesn't trace data sources)
- ControlFlowAnalyzer is a stub (doesn't analyze control flow)
- WeightedRegimePropagator is a stub (doesn't propagate)

You'd see all functions gray (unclassified).

### Phase 3: Complete Analysis Classes (Fresh Session Task)

To get real results on real firmware, you need to:

1. **Complete InputSourceTagger**
   - File: `src/main/java/chokmah/plugin/attestation/analysis/InputSourceTagger.java`
   - Purpose: For each function, find all memory reads/MMIO accesses and classify them using the memory map
   - Input: Function, MemoryRegion list (from JSON parser)
   - Output: List<InputSource>

2. **Complete ControlFlowAnalyzer**
   - File: `src/main/java/chokmah/plugin/attestation/analysis/ControlFlowAnalyzer.java`
   - Purpose: Detect loop bounds, indirect control flow, floating point ops
   - Input: Function, HighFunction (decompiled IR)
   - Output: ControlFlowProperties (already has the data structure)
   - Note: Analyze method exists and returns the right type; implementation needs TODOs filled in

3. **Wire FunctionRegimeAnalyzer**
   - File: `src/main/java/chokmah/plugin/attestation/analysis/FunctionRegimeAnalyzer.java`
   - Purpose: Call all 5 pipeline steps in order and return RegimeClassification
   - This is the entry point that RegimeAnalysisTask calls

4. **Test on STM32F407 firmware**
   - Import binary → Load memory map → Classify All Functions
   - Verify regime distribution looks sensible
   - Spot-check color-coded functions in Listing view

---

## Quick Reference: What's Needed to Go Live

| Step | Blocker | Work Required |
|------|---------|--------------|
| Install plugin ZIP | No | Already works |
| Load JSON memory map | No | Already works |
| Run "Classify All Functions" | **Yes** | Wire InputSourceTagger, ControlFlowAnalyzer, FunctionRegimeAnalyzer |
| See color-coded functions | **Yes** | Same as above |
| Generate report | Maybe | RegimeReportGenerator scaffolded |

---

## Expected Regime Distribution (STM32F407 + OpenPLC)

If InputSourceTagger and ControlFlowAnalyzer work correctly:

- **Regime 1 (green)**: ~30% — timers, watchdogs, internal logic, crypto accelerator
- **Regime 2 (yellow)**: ~10% — ADC reads, sensor processing
- **Regime 3a (red)**: ~50% — UART/Ethernet handlers, CAN logic, USB
- **Unclassified (gray)**: ~10% — functions with no detected data sources (indicates InputSourceTagger issues)

If you see mostly gray after running the plugin, the analysis classes didn't initialize correctly.

---

## For a Fresh Session

Save this context:
- The plugin builds but the analysis classes are stubs
- Pure-Java logic is tested; Ghidra integration is the blocker
- To test with real firmware, complete InputSourceTagger + ControlFlowAnalyzer + wire FunctionRegimeAnalyzer
- The decision tree (RegimeAssigner) is production-ready and can be used as a correctness reference
