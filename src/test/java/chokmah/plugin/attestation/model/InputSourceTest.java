package chokmah.plugin.attestation.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InputSourceTest {

    @Test
    void testDefaultRegimeConstant() {
        InputSource source = new InputSource(InputSource.SourceType.CONSTANT, null, "ROM");
        assertEquals(AttestationRegime.REGIME_1, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeSensorAdc() {
        InputSource source = new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC1");
        assertEquals(AttestationRegime.REGIME_2, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeNetworkComms() {
        InputSource source = new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "UART1");
        assertEquals(AttestationRegime.REGIME_3A, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeUnclassifiedExt() {
        InputSource source = new InputSource(InputSource.SourceType.UNCLASSIFIED_EXT, null, "Unknown ext");
        assertEquals(AttestationRegime.REGIME_3A, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeMmioUnknown() {
        InputSource source = new InputSource(InputSource.SourceType.MMIO_UNKNOWN, null, "Unknown MMIO");
        assertEquals(AttestationRegime.REGIME_3A, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeInternalStateWithoutInherited() {
        InputSource source = new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "global_state");
        assertEquals(AttestationRegime.UNCLASSIFIED, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeInternalStateWithInheritedRegime1() {
        InputSource source = new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "global_state",
                AttestationRegime.REGIME_1);
        assertEquals(AttestationRegime.REGIME_1, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeInternalStateWithInheritedRegime2() {
        InputSource source = new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "global_state",
                AttestationRegime.REGIME_2);
        assertEquals(AttestationRegime.REGIME_2, source.defaultRegime());
    }

    @Test
    void testDefaultRegimeInternalStateWithInheritedRegime3A() {
        InputSource source = new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "global_state",
                AttestationRegime.REGIME_3A);
        assertEquals(AttestationRegime.REGIME_3A, source.defaultRegime());
    }

    @Test
    void testGetSourceType() {
        InputSource source = new InputSource(InputSource.SourceType.CONSTANT, null, "test");
        assertEquals(InputSource.SourceType.CONSTANT, source.getSourceType());
    }

    @Test
    void testGetDescription() {
        InputSource source = new InputSource(InputSource.SourceType.SENSOR_ADC, null, "ADC1 reading");
        assertEquals("ADC1 reading", source.getDescription());
    }

    @Test
    void testGetAccessAddress() {
        InputSource source = new InputSource(InputSource.SourceType.NETWORK_COMMS, null, "UART");
        assertNull(source.getAccessAddress());
    }

    @Test
    void testGetInheritedRegime() {
        InputSource source = new InputSource(InputSource.SourceType.INTERNAL_STATE, null, "state",
                AttestationRegime.REGIME_2);
        assertEquals(AttestationRegime.REGIME_2, source.getInheritedRegime());
    }
}
