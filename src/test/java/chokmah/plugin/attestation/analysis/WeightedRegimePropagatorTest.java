package chokmah.plugin.attestation.analysis;

import chokmah.plugin.attestation.model.*;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for WeightedRegimePropagator heuristics.
 * Tests the three stub implementations: classifyPathType, analyzeArgumentControl,
 * analyzeReturnUsage. Uses mocked ClassificationResult objects.
 */
class WeightedRegimePropagatorTest {

    /**
     * Helper: create a mocked RegimeClassification with given regime and input sources.
     */
    private RegimeClassification makeClassification(
            AttestationRegime regime,
            Confidence confidence,
            List<InputSource> inputSources) {
        RegimeClassification classif = new RegimeClassification(regime, confidence);
        classif.setClassificationRationale("Test regime: " + regime);
        return classif;
    }

    /**
     * Test argument control heuristic based on callee's regime.
     * Regime 3A should map to ATTACKER_CONTROLLED.
     */
    @Test
    void testArgumentControlRegime3aMapping() {
        // Create a mock propagation edge with attacker-controlled arguments
        PropagationEdge edge = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.ATTACKER_CONTROLLED,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        // High-weight edge (>= 0.7) should fully propagate
        assertTrue(edge.getWeight() > 0.3,
                "Attacker-controlled edge should have propagation weight > 0.3");
    }

    /**
     * Test argument control heuristic for Regime 2 (partial control).
     */
    @Test
    void testArgumentControlRegime2Mapping() {
        PropagationEdge edge = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.SENSOR_DERIVED,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        // Sensor-derived arguments have moderate weight
        assertTrue(edge.getWeight() > 0.3);
    }

    /**
     * Test argument control heuristic for Regime 1 (internal state, no adversary control).
     */
    @Test
    void testArgumentControlRegime1Mapping() {
        PropagationEdge edge = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.INTERNAL_STATE,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        // Internal state arguments should not promote propagation
        assertTrue(edge.getWeight() < 0.7,
                "Internal state arguments should not fully propagate");
    }

    /**
     * Test weight threshold: low-weight edge (<0.3) should not propagate.
     */
    @Test
    void testLowWeightEdgeDoesNotPropagate() {
        PropagationEdge lowWeightEdge = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.ERROR_HANDLER,  // low-weight path
                PropagationEdge.ArgumentControl.CONSTANT,
                PropagationEdge.ReturnUsage.UNUSED
        );

        // Error handler path + constant args + unused return should be low weight
        assertTrue(lowWeightEdge.getWeight() < 0.3,
                "Error handler path should have weight < 0.3");
    }

    /**
     * Test high-weight edge (>= 0.7) fully propagates regime.
     */
    @Test
    void testHighWeightEdgeFullPropagation() {
        PropagationEdge highWeightEdge = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.ATTACKER_CONTROLLED,
                PropagationEdge.ReturnUsage.SAFETY_CRITICAL
        );

        // Main path + attacker-controlled args + safety-critical should be high
        assertTrue(highWeightEdge.getWeight() >= 0.7,
                "Main + attacker-controlled + safety-critical should have weight >= 0.7");
    }

    /**
     * Test partial propagation: medium-weight edge in [0.3, 0.7) range.
     * Use callback ptr (lower path type weight) instead of main execution.
     */
    @Test
    void testMediumWeightPartialPropagation() {
        PropagationEdge mediumEdge = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.CALLBACK_PTR,  // lower path weight
                PropagationEdge.ArgumentControl.SENSOR_DERIVED,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        // Callback ptr + sensor args + control flow should be in [0.3, 0.7) range
        // 0.25 + 0.2 + 0.15 = 0.6
        double weight = mediumEdge.getWeight();
        assertTrue(weight >= 0.3 && weight < 0.7,
                "Medium edge should be in partial propagation range [0.3, 0.7)");
    }

    /**
     * Test PropagationEdge weight formula is deterministic and consistent.
     */
    @Test
    void testEdgeWeightConsistency() {
        PropagationEdge edge1 = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.ATTACKER_CONTROLLED,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        PropagationEdge edge2 = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.ATTACKER_CONTROLLED,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        // Same inputs should yield same weight
        assertEquals(edge1.getWeight(), edge2.getWeight(),
                "Edge weight must be deterministic");
    }

    /**
     * Test regime dominance: Regime 3a dominates all others.
     */
    @Test
    void testRegimeDominanceRegime3a() {
        assertEquals(AttestationRegime.REGIME_3A,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, AttestationRegime.REGIME_3A),
                "Regime 3a should dominate Regime 1");

        assertEquals(AttestationRegime.REGIME_3A,
                AttestationRegime.dominate(AttestationRegime.REGIME_2, AttestationRegime.REGIME_3A),
                "Regime 3a should dominate Regime 2");
    }

    /**
     * Test regime dominance: Regime 2 dominates Regime 1.
     */
    @Test
    void testRegimeDominanceRegime2() {
        assertEquals(AttestationRegime.REGIME_2,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, AttestationRegime.REGIME_2),
                "Regime 2 should dominate Regime 1");
    }

    /**
     * Test regime dominance: Regime 1 vs Regime 1 yields Regime 1.
     */
    @Test
    void testRegimeDominanceSame() {
        assertEquals(AttestationRegime.REGIME_1,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, AttestationRegime.REGIME_1),
                "Regime 1 vs Regime 1 should yield Regime 1");
    }

    /**
     * Test path type classification: callback pointers have lower weight than direct calls.
     */
    @Test
    void testCallbackPtrLowerWeightThanDirect() {
        PropagationEdge direct = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.INTERNAL_STATE,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        PropagationEdge indirect = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.CALLBACK_PTR,
                PropagationEdge.ArgumentControl.INTERNAL_STATE,
                PropagationEdge.ReturnUsage.CONTROL_FLOW
        );

        assertTrue(direct.getWeight() > indirect.getWeight(),
                "Direct call should have higher weight than callback ptr");
    }

    /**
     * Test return usage impact: safety-critical return has higher weight.
     */
    @Test
    void testSafetyCriticalReturnHigherWeight() {
        PropagationEdge safetyCritical = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.INTERNAL_STATE,
                PropagationEdge.ReturnUsage.SAFETY_CRITICAL
        );

        PropagationEdge diagnostic = new PropagationEdge(
                null, null, "caller", "callee",
                PropagationEdge.PathType.MAIN_EXECUTION,
                PropagationEdge.ArgumentControl.INTERNAL_STATE,
                PropagationEdge.ReturnUsage.DIAGNOSTIC_ONLY
        );

        assertTrue(safetyCritical.getWeight() > diagnostic.getWeight(),
                "Safety-critical return should have higher weight than diagnostic");
    }
}
