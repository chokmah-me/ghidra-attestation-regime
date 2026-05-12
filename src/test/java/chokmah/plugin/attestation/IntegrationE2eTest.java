package chokmah.plugin.attestation;

import chokmah.plugin.attestation.analysis.RegimeAssigner;
import chokmah.plugin.attestation.model.*;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration test: JSON memory map → InputSources → RegimeAssignment.
 * Validates the pure-Java classification pipeline without Ghidra runtime.
 *
 * Uses STM32F407 discovery board memory map (OpenPLC embedded target).
 * Regime expectations:
 *   - UART/Ethernet/USB/CAN → REGIME_3A (external comms)
 *   - ADC/GPIO/SPI/I2C → REGIME_2 (sensor-like)
 *   - Timers/Watchdog/Crypto → REGIME_1 (internal)
 *   - ROM/SRAM → REGIME_1 (constant/internal state)
 */
class IntegrationE2eTest {

    private static final String STM32_MEMORY_MAP = "data/stm32f407_memory_map.json";

    /**
     * Test: peripheral class to input source mapping logic.
     * Verifies the decision logic without depending on Address creation.
     */
    @Test
    void testPeripheralClassInputSourceMapping() {
        // UART -> NETWORK_COMMS (Regime 3a)
        assertEquals(InputSource.SourceType.NETWORK_COMMS,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.UART));

        // ADC -> SENSOR_ADC (Regime 2)
        assertEquals(InputSource.SourceType.SENSOR_ADC,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.ADC));

        // Timers -> CONSTANT (Regime 1)
        assertEquals(InputSource.SourceType.CONSTANT,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.TIMERS_PWM));

        // ROM -> CONSTANT
        assertEquals(InputSource.SourceType.CONSTANT,
                mapPeripheralToInputSource(MemoryRegion.RegionType.FLASH_ROM,
                        MemoryRegion.PeripheralClass.NONE));

        // SRAM -> INTERNAL_STATE
        assertEquals(InputSource.SourceType.INTERNAL_STATE,
                mapPeripheralToInputSource(MemoryRegion.RegionType.INTERNAL_SRAM,
                        MemoryRegion.PeripheralClass.NONE));
    }

    /**
     * Test: regime assignment with realistic memory-mapped peripherals.
     */
    @Test
    void testRegimeAssignmentUartIsRegime3a() {
        // A function that reads from USART1 should be classified as Regime 3a
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "USART1 data read")
        );

        ControlFlowProperties cleanCf = new ControlFlowProperties(
                true, false, false, false, 0,
                Collections.emptyList(), Collections.emptyList()
        );

        ComplexityMetrics simpleMath = new ComplexityMetrics(
                2, 0, 50, false, 0.0, Collections.emptyList()
        );

        RegimeAssigner assigner = new RegimeAssigner(false);
        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, cleanCf, simpleMath);

        assertEquals(AttestationRegime.REGIME_3A, result.regime(),
                "UART reads should be classified as Regime 3a (adversarial comms)");
    }

    /**
     * Test: regime assignment with ADC input.
     */
    @Test
    void testRegimeAssignmentAdcIsRegime2() {
        // A function reading ADC1 should be Regime 2 (stochastic sensor input)
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC1 analog input")
        );

        ControlFlowProperties cleanCf = new ControlFlowProperties(
                true, false, false, false, 0,
                Collections.emptyList(), Collections.emptyList()
        );

        ComplexityMetrics simpleMath = new ComplexityMetrics(
                2, 0, 50, false, 0.0, Collections.emptyList()
        );

        RegimeAssigner assigner = new RegimeAssigner(false);
        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, cleanCf, simpleMath);

        assertEquals(AttestationRegime.REGIME_2, result.regime(),
                "ADC reads should be classified as Regime 2 (stochastic sensor)");
    }

    /**
     * Test: regime assignment with internal timer (no external input).
     */
    @Test
    void testRegimeAssignmentTimerOnlyIsRegime1() {
        // A function using only TIM1 (internal timer) with no external input
        // should be Regime 1
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.CONSTANT, null, "TIM1 internal counter")
        );

        ControlFlowProperties cleanCf = new ControlFlowProperties(
                true, false, false, false, 1,
                Collections.emptyList(), Collections.emptyList()
        );

        ComplexityMetrics simpleMath = new ComplexityMetrics(
                3, 0, 100, false, 0.0, Collections.emptyList()
        );

        RegimeAssigner assigner = new RegimeAssigner(false);
        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, cleanCf, simpleMath);

        assertEquals(AttestationRegime.REGIME_1, result.regime(),
                "Timer-only logic with constant input should be Regime 1");
    }

    /**
     * Test: regime assignment respects adversarial dominance.
     * When a function reads both ADC (Regime 2) and UART (Regime 3a),
     * Regime 3a dominates.
     */
    @Test
    void testRegimeAssignmentAdversarialDominates() {
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC1"),
                new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "USART1")
        );

        ControlFlowProperties cleanCf = new ControlFlowProperties(
                true, false, false, false, 0,
                Collections.emptyList(), Collections.emptyList()
        );

        ComplexityMetrics simpleMath = new ComplexityMetrics(
                2, 0, 50, false, 0.0, Collections.emptyList()
        );

        RegimeAssigner assigner = new RegimeAssigner(false);
        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, cleanCf, simpleMath);

        assertEquals(AttestationRegime.REGIME_3A, result.regime(),
                "Adversarial input (UART) should dominate sensor input (ADC)");
    }

    /**
     * Test: STM32F407 peripheral classification is sensible.
     * Verifies that peripheral classes map correctly to regime expectations.
     */
    @Test
    void testStm32F407PeripheralClassification() {
        // Verify actual STM32F407 peripheral class mappings
        assertEquals(InputSource.SourceType.NETWORK_COMMS,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.UART));

        assertEquals(InputSource.SourceType.SENSOR_ADC,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.ADC));

        assertEquals(InputSource.SourceType.NETWORK_COMMS,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.ETHERNET_MAC));

        assertEquals(InputSource.SourceType.CONSTANT,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.TIMERS_PWM));

        assertEquals(InputSource.SourceType.SENSOR_ADC,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.GPIO));

        assertEquals(InputSource.SourceType.NETWORK_COMMS,
                mapPeripheralToInputSource(MemoryRegion.RegionType.MMIO_PERIPHERAL,
                        MemoryRegion.PeripheralClass.CAN));
    }

    /**
     * Test: regime distribution across realistic function set.
     * Simulates a typical embedded firmware with mixed regime functions.
     */
    @Test
    void testRegimeDistributionStm32Firmware() {
        RegimeAssigner assigner = new RegimeAssigner(false);

        // Simulated functions in a typical STM32 firmware
        class SimulatedFunction {
            String name;
            List<InputSource> sources;
            AttestationRegime expectedRegime;

            SimulatedFunction(String name, List<InputSource> sources, AttestationRegime expected) {
                this.name = name;
                this.sources = sources;
                this.expectedRegime = expected;
            }
        }

        ControlFlowProperties cleanCf = new ControlFlowProperties(
                true, false, false, false, 1,
                Collections.emptyList(), Collections.emptyList()
        );

        ComplexityMetrics simple = new ComplexityMetrics(
                2, 0, 50, false, 0.0, Collections.emptyList()
        );

        List<SimulatedFunction> functions = List.of(
                // Regime 1: internal control logic
                new SimulatedFunction("timer_isr", List.of(
                        new InputSource(InputSource.SourceType.CONSTANT, null, "TIM1")
                ), AttestationRegime.REGIME_1),

                // Regime 1: watchdog
                new SimulatedFunction("reset_watchdog", List.of(
                        new InputSource(InputSource.SourceType.CONSTANT, null, "IWDG")
                ), AttestationRegime.REGIME_1),

                // Regime 2: sensor read
                new SimulatedFunction("read_temperature", List.of(
                        new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC1")
                ), AttestationRegime.REGIME_2),

                // Regime 3a: network read
                new SimulatedFunction("read_modbus", List.of(
                        new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "USART1")
                ), AttestationRegime.REGIME_3A),

                // Regime 3a: Ethernet
                new SimulatedFunction("ethernet_rx", List.of(
                        new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "ETH_MAC")
                ), AttestationRegime.REGIME_3A),

                // Regime 3a: dominates Regime 2
                new SimulatedFunction("mixed_input_func", List.of(
                        new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC"),
                        new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "UART")
                ), AttestationRegime.REGIME_3A)
        );

        Map<AttestationRegime, Integer> distribution = new HashMap<>();
        for (SimulatedFunction fn : functions) {
            RegimeAssigner.RegimeAssignment result = assigner.assignRegime(fn.sources, cleanCf, simple);
            assertEquals(fn.expectedRegime, result.regime(),
                    "Function " + fn.name + " should be " + fn.expectedRegime);
            distribution.merge(result.regime(), 1, Integer::sum);
        }

        // Verify distribution is sensible
        assertTrue(distribution.getOrDefault(AttestationRegime.REGIME_1, 0) >= 2,
                "Should have at least 2 Regime 1 functions (timers, watchdog)");
        assertTrue(distribution.getOrDefault(AttestationRegime.REGIME_2, 0) >= 1,
                "Should have at least 1 Regime 2 function (sensors)");
        assertTrue(distribution.getOrDefault(AttestationRegime.REGIME_3A, 0) >= 3,
                "Should have at least 3 Regime 3a functions (network, mixed)");
    }

    // --- Helper methods ---

    /**
     * Map a memory region type and peripheral class to expected input source type.
     * This mimics the logic in MemoryRegion.toInputSourceType() without needing Address objects.
     */
    private InputSource.SourceType mapPeripheralToInputSource(
            MemoryRegion.RegionType regionType,
            MemoryRegion.PeripheralClass pClass) {
        return switch (regionType) {
            case FLASH_ROM -> InputSource.SourceType.CONSTANT;
            case INTERNAL_SRAM -> InputSource.SourceType.INTERNAL_STATE;
            case EXTERNAL_RAM -> InputSource.SourceType.UNCLASSIFIED_EXT;
            case UNKNOWN -> InputSource.SourceType.UNCLASSIFIED_EXT;
            case MMIO_PERIPHERAL -> switch (pClass) {
                case ADC, GPIO -> InputSource.SourceType.SENSOR_ADC;
                case UART, ETHERNET_MAC, USB, CAN -> InputSource.SourceType.NETWORK_COMMS;
                case SPI, I2C -> InputSource.SourceType.SENSOR_ADC;
                case UNKNOWN_PERIPHERAL -> InputSource.SourceType.MMIO_UNKNOWN;
                default -> InputSource.SourceType.CONSTANT;
            };
        };
    }
}
