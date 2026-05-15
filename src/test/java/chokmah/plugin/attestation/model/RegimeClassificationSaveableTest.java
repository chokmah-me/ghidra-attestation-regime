package chokmah.plugin.attestation.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RegimeClassificationSaveableTest {

    @Test
    void testSchemaVersion() {
        RegimeClassification rc = new RegimeClassification();
        assertEquals(1, rc.getSchemaVersion());
    }

    @Test
    void testDefaultConstructor() {
        RegimeClassification rc = new RegimeClassification();
        assertEquals(AttestationRegime.UNCLASSIFIED, rc.getRegime());
        assertEquals(Confidence.LOW, rc.getConfidence());
        assertEquals(0.0, rc.getProvenanceCheckScore());
        assertEquals("", rc.getClassificationRationale());
    }

    @Test
    void testFieldContract() {
        RegimeClassification rc = new RegimeClassification();
        Class<?>[] fields = rc.getObjectStorageFields();
        assertEquals(4, fields.length);
        assertEquals(String.class, fields[0]);
        assertEquals(String.class, fields[1]);
        assertEquals(Double.class, fields[2]);
        assertEquals(String.class, fields[3]);
    }

    @Test
    void testSettersGetters_Regime1_High() {
        RegimeClassification rc = new RegimeClassification(
            AttestationRegime.REGIME_1,
            Confidence.HIGH
        );
        rc.setProvenanceCheckScore(0.5);
        rc.setClassificationRationale("Test reason");

        assertEquals(AttestationRegime.REGIME_1, rc.getRegime());
        assertEquals(Confidence.HIGH, rc.getConfidence());
        assertEquals(0.5, rc.getProvenanceCheckScore());
        assertEquals("Test reason", rc.getClassificationRationale());
    }

    @Test
    void testSettersGetters_Regime2_Medium() {
        RegimeClassification rc = new RegimeClassification(
            AttestationRegime.REGIME_2,
            Confidence.MEDIUM
        );
        rc.setProvenanceCheckScore(0.75);
        rc.setClassificationRationale("Analysis complete");

        assertEquals(AttestationRegime.REGIME_2, rc.getRegime());
        assertEquals(Confidence.MEDIUM, rc.getConfidence());
        assertEquals(0.75, rc.getProvenanceCheckScore());
        assertEquals("Analysis complete", rc.getClassificationRationale());
    }

    @Test
    void testSettersGetters_Regime3a_Low() {
        RegimeClassification rc = new RegimeClassification(
            AttestationRegime.REGIME_3A,
            Confidence.LOW
        );
        rc.setProvenanceCheckScore(0.2);
        rc.setClassificationRationale("External input detected");

        assertEquals(AttestationRegime.REGIME_3A, rc.getRegime());
        assertEquals(Confidence.LOW, rc.getConfidence());
        assertEquals(0.2, rc.getProvenanceCheckScore());
        assertEquals("External input detected", rc.getClassificationRationale());
    }

    @Test
    void testSettersGetters_Provenance() {
        RegimeClassification rc = new RegimeClassification(
            AttestationRegime.PROVENANCE_CHECK,
            Confidence.MEDIUM
        );
        rc.setProvenanceCheckScore(0.88);
        rc.setClassificationRationale("Cryptographic operation");

        assertEquals(AttestationRegime.PROVENANCE_CHECK, rc.getRegime());
        assertEquals(Confidence.MEDIUM, rc.getConfidence());
        assertEquals(0.88, rc.getProvenanceCheckScore());
        assertEquals("Cryptographic operation", rc.getClassificationRationale());
    }

    @Test
    void testSettersGetters_Unclassified() {
        RegimeClassification rc = new RegimeClassification(
            AttestationRegime.UNCLASSIFIED,
            Confidence.LOW
        );
        rc.setProvenanceCheckScore(0.0);
        rc.setClassificationRationale("");

        assertEquals(AttestationRegime.UNCLASSIFIED, rc.getRegime());
        assertEquals(Confidence.LOW, rc.getConfidence());
        assertEquals(0.0, rc.getProvenanceCheckScore());
        assertEquals("", rc.getClassificationRationale());
    }

    @Test
    void testRationalePreservation() {
        RegimeClassification rc = new RegimeClassification();
        String longRationale = "Complex control flow with volatile memory access and external input sources detected";
        rc.setClassificationRationale(longRationale);

        assertEquals(longRationale, rc.getClassificationRationale());
    }

    @Test
    void testNullRationaleDefaultsToEmpty() {
        RegimeClassification rc = new RegimeClassification();
        rc.setClassificationRationale(null);

        // The class should treat null rationale as empty string in save()
        assertNull(rc.getClassificationRationale());
    }

    @Test
    void testAllRegimes_PropertyAccess() {
        for (AttestationRegime regime : AttestationRegime.values()) {
            RegimeClassification rc = new RegimeClassification(regime, Confidence.MEDIUM);
            rc.setProvenanceCheckScore(0.5);
            rc.setClassificationRationale("Test " + regime.name());

            assertEquals(regime, rc.getRegime());
            assertEquals(Confidence.MEDIUM, rc.getConfidence());
            assertEquals(0.5, rc.getProvenanceCheckScore());
            assertEquals("Test " + regime.name(), rc.getClassificationRationale());
        }
    }

    @Test
    void testAllConfidences_PropertyAccess() {
        for (Confidence confidence : Confidence.values()) {
            RegimeClassification rc = new RegimeClassification(
                AttestationRegime.REGIME_2,
                confidence
            );
            rc.setProvenanceCheckScore(0.6);
            rc.setClassificationRationale("Confidence " + confidence.name());

            assertEquals(AttestationRegime.REGIME_2, rc.getRegime());
            assertEquals(confidence, rc.getConfidence());
            assertEquals(0.6, rc.getProvenanceCheckScore());
            assertEquals("Confidence " + confidence.name(), rc.getClassificationRationale());
        }
    }

    @Test
    void testIsUpgradeable_False() {
        RegimeClassification rc = new RegimeClassification();
        assertFalse(rc.isUpgradeable(0));
        assertFalse(rc.isUpgradeable(1));
        assertFalse(rc.isUpgradeable(2));
    }

    @Test
    void testIsPrivate_False() {
        RegimeClassification rc = new RegimeClassification();
        assertFalse(rc.isPrivate());
    }

    @Test
    void testSerializationFieldOrder_SaveContract() {
        RegimeClassification rc = new RegimeClassification(
            AttestationRegime.REGIME_1,
            Confidence.HIGH
        );
        rc.setProvenanceCheckScore(0.42);
        rc.setClassificationRationale("Field order test");

        // Verify save() contracts match field order
        Class<?>[] fields = rc.getObjectStorageFields();
        assertEquals(4, fields.length);

        // Field 0: regime.name() -> String
        assertEquals(String.class, fields[0]);
        // Field 1: confidence.name() -> String
        assertEquals(String.class, fields[1]);
        // Field 2: provenanceCheckScore -> Double
        assertEquals(Double.class, fields[2]);
        // Field 3: classificationRationale -> String
        assertEquals(String.class, fields[3]);
    }

    @Test
    void testTimestampTracking() {
        long beforeCreation = System.currentTimeMillis();
        RegimeClassification rc = new RegimeClassification(
            AttestationRegime.REGIME_1,
            Confidence.MEDIUM
        );
        long afterCreation = System.currentTimeMillis();

        long timestamp = rc.getClassificationTimestamp();
        assertTrue(timestamp >= beforeCreation, "Timestamp should be set to creation time or later");
        assertTrue(timestamp <= afterCreation, "Timestamp should not be after creation");
    }

    @Test
    void testPropagatedFlag_DefaultFalse() {
        RegimeClassification rc = new RegimeClassification();
        assertFalse(rc.isPropagated(), "Default classification should not be propagated");
    }

    @Test
    void testInputSourcesEmpty_DefaultConstruction() {
        RegimeClassification rc = new RegimeClassification();
        var sources = rc.getInputSources();
        assertTrue(sources.isEmpty(), "Default classification should have no input sources");
    }

    @Test
    void testPropagationPathEmpty_DefaultConstruction() {
        RegimeClassification rc = new RegimeClassification();
        var path = rc.getPropagationPath();
        assertTrue(path.isEmpty(), "Default classification should have empty propagation path");
    }
}
