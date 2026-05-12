package chokmah.plugin.attestation.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AttestationRegimeTest {

    @Test
    void testDominateRegime3ABeatsAll() {
        assertEquals(AttestationRegime.REGIME_3A,
                AttestationRegime.dominate(AttestationRegime.REGIME_3A, AttestationRegime.REGIME_1));
        assertEquals(AttestationRegime.REGIME_3A,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, AttestationRegime.REGIME_3A));
        assertEquals(AttestationRegime.REGIME_3A,
                AttestationRegime.dominate(AttestationRegime.REGIME_3A, AttestationRegime.REGIME_2));
    }

    @Test
    void testDominateProvenanceBeatsRegime2and1() {
        assertEquals(AttestationRegime.PROVENANCE_CHECK,
                AttestationRegime.dominate(AttestationRegime.PROVENANCE_CHECK, AttestationRegime.REGIME_2));
        assertEquals(AttestationRegime.PROVENANCE_CHECK,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, AttestationRegime.PROVENANCE_CHECK));
    }

    @Test
    void testDominateRegime2BeatsRegime1() {
        assertEquals(AttestationRegime.REGIME_2,
                AttestationRegime.dominate(AttestationRegime.REGIME_2, AttestationRegime.REGIME_1));
        assertEquals(AttestationRegime.REGIME_2,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, AttestationRegime.REGIME_2));
    }

    @Test
    void testDominateSameRegime() {
        assertEquals(AttestationRegime.REGIME_1,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, AttestationRegime.REGIME_1));
        assertEquals(AttestationRegime.REGIME_3A,
                AttestationRegime.dominate(AttestationRegime.REGIME_3A, AttestationRegime.REGIME_3A));
    }

    @Test
    void testDominateWithNull() {
        assertEquals(AttestationRegime.REGIME_2,
                AttestationRegime.dominate(null, AttestationRegime.REGIME_2));
        assertEquals(AttestationRegime.REGIME_1,
                AttestationRegime.dominate(AttestationRegime.REGIME_1, null));
        assertNull(AttestationRegime.dominate(null, null));
    }

    @Test
    void testDominateUnclassifiedBeatsNothing() {
        assertEquals(AttestationRegime.REGIME_1,
                AttestationRegime.dominate(AttestationRegime.UNCLASSIFIED, AttestationRegime.REGIME_1));
        assertEquals(AttestationRegime.REGIME_2,
                AttestationRegime.dominate(AttestationRegime.REGIME_2, AttestationRegime.UNCLASSIFIED));
    }

    @Test
    void testIsAdversarialRegime3A() {
        assertTrue(AttestationRegime.REGIME_3A.isAdversarial());
    }

    @Test
    void testIsAdversarialProvenance() {
        assertTrue(AttestationRegime.PROVENANCE_CHECK.isAdversarial());
    }

    @Test
    void testIsAdversarialRegime1False() {
        assertFalse(AttestationRegime.REGIME_1.isAdversarial());
    }

    @Test
    void testIsAdversarialRegime2False() {
        assertFalse(AttestationRegime.REGIME_2.isAdversarial());
    }

    @Test
    void testIsAdversarialUnclassifiedFalse() {
        assertFalse(AttestationRegime.UNCLASSIFIED.isAdversarial());
    }

    @Test
    void testGetLabel() {
        assertEquals("Regime 1", AttestationRegime.REGIME_1.getLabel());
        assertEquals("Regime 2", AttestationRegime.REGIME_2.getLabel());
        assertEquals("Regime 3a", AttestationRegime.REGIME_3A.getLabel());
        assertEquals("Provenance Check", AttestationRegime.PROVENANCE_CHECK.getLabel());
        assertEquals("Unclassified", AttestationRegime.UNCLASSIFIED.getLabel());
    }

    @Test
    void testGetColorArgb() {
        assertEquals(0xFF4CAF50, AttestationRegime.REGIME_1.getColorArgb());
        assertEquals(0xFFFFEB3B, AttestationRegime.REGIME_2.getColorArgb());
        assertEquals(0xFFF44336, AttestationRegime.REGIME_3A.getColorArgb());
        assertEquals(0xFFFF9800, AttestationRegime.PROVENANCE_CHECK.getColorArgb());
        assertEquals(0xFF9E9E9E, AttestationRegime.UNCLASSIFIED.getColorArgb());
    }
}
