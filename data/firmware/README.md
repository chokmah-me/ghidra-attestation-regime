# Firmware Test Collection

This directory contains a curated collection of ARM Cortex-M ELF firmware binaries for testing the attestation regime classifier on realistic embedded firmware.

## Overview

**9 pre-built ELF files** from Renode (Antmicro CDN), spanning three attestation regimes:

- **Regime 1** (deterministic): Timer examples, simple HAL
- **Regime 2** (sensor/cooperative): RTC reads, ADC inputs
- **Regime 3a** (adversarial input): GPIO interrupts from external pins
- **Provenance** (unknown tables): CRC test firmware

See `manifest.json` for details.

## Files

### Downloaded (`download/`)

9 ELF files (~9MB total), pre-built from Renode test suite. URLs verified as live.

- `zephyr-hello_world_stm32f4.elf` — Zephyr OS, UART output
- `riot-rtc_stm32f4.elf` — RIOT OS, RTC volatile reads
- `timer-upcount_stm32f4.elf` — Timer PWM, no external input
- `timer-downcount_stm32f4.elf` — Timer PWM, no external input
- `cubemx-hello_world_stm32f4.elf` — STM32CubeMX HAL template
- `faultmask_stm32f4.elf` — Exception masking test
- `zephyr-button_stm32f103.elf` — GPIO interrupt from external button
- `crc-test_stm32f0.elf` — CRC table lookups (fingerprinting test)
- `tock_kernel_stm32f412.elf` — Full Tock OS kernel (large, mixed regimes)

### Built (from PlatformIO projects)

3 ELF files compiled from STM32CubeF4 examples (optional, currently deferred due to build setup complexity).

### Results (`results/`)

JSON files containing regime classification results per ELF.

```json
{
  "firmware": "zephyr-hello_world_stm32f4.elf",
  "totalFunctions": 142,
  "regimeCounts": {
    "REGIME_1": 95,
    "REGIME_2": 35,
    "REGIME_3A": 8,
    "PROVENANCE": 2,
    "UNCLASSIFIED": 2
  },
  "functionDetails": [...]
}
```

## Usage

### 1. Download firmware

```powershell
# From repo root
.\scripts\fetch_firmware.ps1
```

Downloads all 9 ELFs to `data/firmware/download/`.

### 2. Analyze with Ghidra (headless)

```powershell
# From repo root
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21.0.11"
$env:GHIDRA_INSTALL_DIR = "C:\Tools\ghidra_12.0.4_PUBLIC"

.\scripts\run_firmware_analysis.ps1
```

Runs GhidraScript on each ELF, outputs JSON to `data/firmware/results/`.

### 3. Analyze manually in Ghidra GUI

1. Import ELF file
2. Run auto-analysis (`Ctrl+E`)
3. Mark MMIO regions as volatile in Data Type Manager (critical)
4. Tools > Attestation Regime > Load Memory Map > `data/stm32f407_memory_map.json`
5. Tools > Attestation Regime > Classify All Functions
6. Review Listing view (color-coded margins per regime)

## Expected Results

| Firmware | Expected regime | Why |
|----------|---|---|
| `timer-*.elf` | **Regime 1** 95%+ | Timer only, no external input |
| `zephyr-hello_world_stm32f4.elf` | **Regime 1/2** 70-80% | UART output, deterministic |
| `riot-rtc_stm32f4.elf` | **Regime 2/3a** 40-50% | RTC volatile reads, async |
| `zephyr-button_stm32f103.elf` | **Regime 3a** 30-40% | GPIO interrupt, external pin |
| `crc-test_stm32f0.elf` | **Provenance** 30-40% | CRC tables (KnownConstantTables) |
| `tock_kernel_stm32f412.elf` | **Mixed** 30-30-20-15% | Full OS kernel, all regimes |

## Architecture (Target)

The analysis pipeline:

```
ELF binary
    ↓
Ghidra import + auto-analysis
    ↓
InputSourceTagger (trace inputs to MMIO, constants, sensors)
    ↓
ControlFlowAnalyzer (loop bounds, indirect branches, hasFunctionPointerUsage)
    ↓
ComplexityAnalyzer (cyclomatic, table sizes, pcode op count)
    ↓
RegimeAssigner (decision tree: adversarial → Regime 3a, sensor → Regime 2, etc.)
    ↓
WeightedRegimePropagator (propagate through call graph)
    ↓
JSON output (regimeCounts, functionDetails)
```

Currently implemented: pure-Java model (RegimeAssigner, WeightedRegimePropagator).
Scaffolded but Ghidra-runtime dependent: InputSourceTagger, ControlFlowAnalyzer, ComplexityAnalyzer.

## References

- Bilar (2026) *Three Regimes of Capability Attestation* — theoretical foundation
- Bilar (2026) *The Computability Filter* — classification rules
- Renode (Antmicro CDN) — pre-built firmware source
- STM32CubeF4 — example firmware sources

## Notes

- `.gitignore` excludes `data/firmware/download/` and `data/firmware/built/` (ELFs are large)
- `manifest.json` is committed; results JSON is committed (for regression testing)
- Memory map (`data/stm32f407_memory_map.json`) is critical for meaningful results; without it, classification defaults to heuristic (lower confidence)
- MMIO regions must be marked volatile in Ghidra before classification (affects decompiler behavior)
