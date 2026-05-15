package chokmah.plugin.attestation.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MemoryRegionTest {

    @Test
    void testToInputSourceTypeFlashRom() {
        MemoryRegion region = new MemoryRegion(
                "Flash", null, null,
                MemoryRegion.RegionType.FLASH_ROM,
                MemoryRegion.PeripheralClass.NONE, false
        );
        assertEquals(InputSource.SourceType.CONSTANT, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypeInternalSram() {
        MemoryRegion region = new MemoryRegion(
                "SRAM", null, null,
                MemoryRegion.RegionType.INTERNAL_SRAM,
                MemoryRegion.PeripheralClass.NONE, false
        );
        assertEquals(InputSource.SourceType.INTERNAL_STATE, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypeExternalRam() {
        MemoryRegion region = new MemoryRegion(
                "ExtRAM", null, null,
                MemoryRegion.RegionType.EXTERNAL_RAM,
                MemoryRegion.PeripheralClass.NONE, false
        );
        assertEquals(InputSource.SourceType.UNCLASSIFIED_EXT, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypeUnknown() {
        MemoryRegion region = new MemoryRegion(
                "Unknown", null, null,
                MemoryRegion.RegionType.UNKNOWN,
                MemoryRegion.PeripheralClass.NONE, false
        );
        assertEquals(InputSource.SourceType.UNCLASSIFIED_EXT, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypePeripheralAdc() {
        MemoryRegion region = new MemoryRegion(
                "ADC1", null, null,
                MemoryRegion.RegionType.MMIO_PERIPHERAL,
                MemoryRegion.PeripheralClass.ADC, true
        );
        assertEquals(InputSource.SourceType.SENSOR_ADC, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypePeripheralUart() {
        MemoryRegion region = new MemoryRegion(
                "UART1", null, null,
                MemoryRegion.RegionType.MMIO_PERIPHERAL,
                MemoryRegion.PeripheralClass.UART, true
        );
        assertEquals(InputSource.SourceType.NETWORK_COMMS, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypePeripheralEthernetMac() {
        MemoryRegion region = new MemoryRegion(
                "ETH", null, null,
                MemoryRegion.RegionType.MMIO_PERIPHERAL,
                MemoryRegion.PeripheralClass.ETHERNET_MAC, true
        );
        assertEquals(InputSource.SourceType.NETWORK_COMMS, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypePeripheralFieldbus() {
        MemoryRegion region = new MemoryRegion(
                "Profibus", null, null,
                MemoryRegion.RegionType.MMIO_PERIPHERAL,
                MemoryRegion.PeripheralClass.FIELDBUS, true
        );
        assertEquals(InputSource.SourceType.FIELDBUS, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypePeripheralUnknown() {
        MemoryRegion region = new MemoryRegion(
                "UnknownPeripheral", null, null,
                MemoryRegion.RegionType.MMIO_PERIPHERAL,
                MemoryRegion.PeripheralClass.UNKNOWN_PERIPHERAL, true
        );
        assertEquals(InputSource.SourceType.MMIO_UNKNOWN, region.toInputSourceType());
    }

    @Test
    void testToInputSourceTypePeripheralTimers() {
        MemoryRegion region = new MemoryRegion(
                "Timers", null, null,
                MemoryRegion.RegionType.MMIO_PERIPHERAL,
                MemoryRegion.PeripheralClass.TIMERS_PWM, false
        );
        assertEquals(InputSource.SourceType.CONSTANT, region.toInputSourceType());
    }
}
