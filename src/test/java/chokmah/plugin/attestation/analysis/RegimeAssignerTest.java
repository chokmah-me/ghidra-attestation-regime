package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.*;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class RegimeAssignerTest {

    private static final ControlFlowAnalyzer.ControlFlowProperties BOUNDED_CLEAN_CF =
            new ControlFlowAnalyzer.ControlFlowProperties(
                    true, // allLoopsBounded
                    false, // hasIndirectControlFlow
                    false, // hasFloatingPoint
                    false, // hasVolatileAccesses
                    1, // loopCount
                    Collections.emptyList(),
                    Collections.emptyList()
            );

    private static final ControlFlowAnalyzer.ControlFlowProperties UNBOUNDED_CF =
            new ControlFlowAnalyzer.ControlFlowProperties(
                    false, // allLoopsBounded
                    false, // hasIndirectControlFlow
                    false, // hasFloatingPoint
                    false, // hasVolatileAccesses
                    1, // loopCount
                    List.of("unbounded while loop"),
                    Collections.emptyList()
            );

    private static final ComplexityAnalyzer.ComplexityMetrics NORMAL_COMPLEXITY =
            new ComplexityAnalyzer.ComplexityMetrics(
                    5, // cyclomaticComplexity
                    0, // lookupTableEntries
                    100, // pcodeOpCount
                    false, // isProvenanceCheckCandidate
                    0.0, // provenanceCheckScore
                    Collections.emptyList()
            );

    private static final ComplexityAnalyzer.ComplexityMetrics PROVENANCE_CANDIDATE =
            new ComplexityAnalyzer.ComplexityMetrics(
                    10, // cyclomaticComplexity
                    512, // lookupTableEntries (suspicious)
                    500, // pcodeOpCount
                    true, // isProvenanceCheckCandidate
                    6.5, // provenanceCheckScore
                    Collections.emptyList()
            );

    @Test
    void testRegime3aNetworkInput() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "UART1")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_3A, result.regime());
        assertEquals(Confidence.MEDIUM, result.confidence());
        assertTrue(result.rationale().contains("Regime 3a"));
    }

    @Test
    void testRegime3aUnclassifiedExtInput() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.UNCLASSIFIED_EXT, null, "Unknown mem")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_3A, result.regime());
    }

    @Test
    void testRegime3aMmioUnknownInput() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.MMIO_UNKNOWN, null, "Unknown MMIO")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_3A, result.regime());
    }

    @Test
    void testRegime3aDominatesRegime2() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC"),
                new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "UART")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_3A, result.regime());
    }

    @Test
    void testProvenanceCheckFlaggedFirst() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.CONSTANT, null, "ROM")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, PROVENANCE_CANDIDATE);
        assertEquals(AttestationRegime.PROVENANCE_CHECK, result.regime());
        assertEquals(Confidence.HIGH, result.confidence());
        assertTrue(result.rationale().contains("provenance check"));
    }

    @Test
    void testRegime1ConstantInputsBoundedLoops() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.CONSTANT, null, "ROM")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_1, result.regime());
        assertEquals(Confidence.HIGH, result.confidence());
        assertTrue(result.rationale().contains("Regime 1"));
    }

    @Test
    void testRegime1AllInternalState() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "global_counter",
                        AttestationRegime.REGIME_1)
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_1, result.regime());
    }

    @Test
    void testRegime2SensorInput() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC1")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_2, result.regime());
        assertEquals(Confidence.MEDIUM, result.confidence());
        assertTrue(result.rationale().contains("Regime 2"));
    }

    @Test
    void testRegime1EmptySourcesList() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = Collections.emptyList();

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_1, result.regime());
        assertEquals(Confidence.MEDIUM, result.confidence());
    }

    @Test
    void testRegime1EmptySourcesWithUnboundedLoops() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = Collections.emptyList();

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, UNBOUNDED_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_1, result.regime());
        assertEquals(Confidence.LOW, result.confidence());
    }

    @Test
    void testUnclassifiedNonStrictMode() {
        RegimeAssigner assigner = new RegimeAssigner(false); // non-strict
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "unknown_global")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.UNCLASSIFIED, result.regime());
        assertEquals(Confidence.LOW, result.confidence());
    }

    @Test
    void testRegime3aStrictMode() {
        RegimeAssigner assigner = new RegimeAssigner(true); // strict
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "unknown_global")
        );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, NORMAL_COMPLEXITY);
        assertEquals(AttestationRegime.REGIME_3A, result.regime());
        assertEquals(Confidence.LOW, result.confidence());
        assertTrue(result.rationale().contains("strict mode"));
    }

    @Test
    void testRegime1FloatingPointDoesNotTriggerRegime1() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.CONSTANT, null, "ROM")
        );

        ControlFlowAnalyzer.ControlFlowProperties cfWithFp =
                new ControlFlowAnalyzer.ControlFlowProperties(
                        true, false, true, false, 1,
                        Collections.emptyList(),
                        Collections.emptyList()
                );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, cfWithFp, NORMAL_COMPLEXITY);
        assertNotEquals(AttestationRegime.REGIME_1, result.regime());
    }

    @Test
    void testRegime1IndirectCFDoesNotTriggerRegime1() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.CONSTANT, null, "ROM")
        );

        ControlFlowAnalyzer.ControlFlowProperties cfWithIndirect =
                new ControlFlowAnalyzer.ControlFlowProperties(
                        true, true, false, false, 1,
                        Collections.emptyList(),
                        List.of("function pointer call")
                );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, cfWithIndirect, NORMAL_COMPLEXITY);
        assertNotEquals(AttestationRegime.REGIME_1, result.regime());
    }

    @Test
    void testRegime1UnboundedLoopsDoNotTriggerRegime1() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.CONSTANT, null, "ROM")
        );

        ControlFlowAnalyzer.ControlFlowProperties cfUnbounded =
                new ControlFlowAnalyzer.ControlFlowProperties(
                        false, false, false, false, 1,
                        List.of("while(1)"),
                        Collections.emptyList()
                );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, cfUnbounded, NORMAL_COMPLEXITY);
        assertNotEquals(AttestationRegime.REGIME_1, result.regime());
    }

    @Test
    void testProvenanceCheckWithLowScore() {
        RegimeAssigner assigner = new RegimeAssigner(false);
        List<InputSource> sources = List.of(
                new InputSource(InputSource.SourceType.CONSTANT, null, "ROM")
        );

        ComplexityAnalyzer.ComplexityMetrics lowScoreProvenance =
                new ComplexityAnalyzer.ComplexityMetrics(
                        5, 256, 100,
                        true, // isProvenanceCheckCandidate
                        3.5, // provenanceCheckScore (low)
                        Collections.emptyList()
                );

        RegimeAssigner.RegimeAssignment result = assigner.assignRegime(sources, BOUNDED_CLEAN_CF, lowScoreProvenance);
        assertEquals(AttestationRegime.PROVENANCE_CHECK, result.regime());
        assertEquals(Confidence.MEDIUM, result.confidence());
    }
}
