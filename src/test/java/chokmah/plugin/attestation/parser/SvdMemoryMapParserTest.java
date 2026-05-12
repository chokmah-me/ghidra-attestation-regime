package chokmah.plugin.attestation.parser;

import chokmah.plugin.attestation.model.*;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SvdMemoryMapParserTest {

    private static final String TEST_JSON_PATH = "data/stm32f407_memory_map.json";

    @Test
    void testParseJsonValidFile() throws Exception {
        // Test that we can parse a valid JSON memory map file
        File jsonFile = new File(TEST_JSON_PATH);
        assertTrue(jsonFile.exists(), "Test fixture " + TEST_JSON_PATH + " not found");

        // Create a minimal mock AddressFactory for parsing
        var addressFactory = MockAddressFactory.create();
        SvdMemoryMapParser parser = new SvdMemoryMapParser(addressFactory);

        List<MemoryRegion> regions = parser.parseJson(jsonFile);
        assertNotNull(regions);
        assertFalse(regions.isEmpty(), "Should parse regions from JSON");
        assertTrue(regions.size() > 30, "Should have parsed all regions (36+ expected)");
    }

    @Test
    void testParseJsonFindsAdc() throws Exception {
        File jsonFile = new File(TEST_JSON_PATH);
        assertTrue(jsonFile.exists());

        MockAddressFactory addressFactory = new MockAddressFactory();
        SvdMemoryMapParser parser = new SvdMemoryMapParser(addressFactory);

        List<MemoryRegion> regions = parser.parseJson(jsonFile);

        // Find ADC regions
        List<MemoryRegion> adcRegions = regions.stream()
                .filter(r -> r.getPeripheralClass() == MemoryRegion.PeripheralClass.ADC)
                .toList();

        assertEquals(3, adcRegions.size(), "Should find ADC1, ADC2, ADC3");
        assertTrue(adcRegions.stream().anyMatch(r -> r.getName().equals("ADC1")));
        assertTrue(adcRegions.stream().anyMatch(r -> r.getName().equals("ADC2")));
        assertTrue(adcRegions.stream().anyMatch(r -> r.getName().equals("ADC3")));
    }

    @Test
    void testParseJsonFindsUart() throws Exception {
        File jsonFile = new File(TEST_JSON_PATH);
        assertTrue(jsonFile.exists());

        MockAddressFactory addressFactory = new MockAddressFactory();
        SvdMemoryMapParser parser = new SvdMemoryMapParser(addressFactory);

        List<MemoryRegion> regions = parser.parseJson(jsonFile);

        // Find UART regions
        List<MemoryRegion> uartRegions = regions.stream()
                .filter(r -> r.getPeripheralClass() == MemoryRegion.PeripheralClass.UART)
                .toList();

        assertEquals(6, uartRegions.size(), "Should find USART1/2/3/6 and UART4/5");
        assertTrue(uartRegions.stream().anyMatch(r -> r.getName().equals("USART1")));
        assertTrue(uartRegions.stream().anyMatch(r -> r.getName().equals("UART5")));
    }

    @Test
    void testParseJsonFindsEthernetMac() throws Exception {
        File jsonFile = new File(TEST_JSON_PATH);
        assertTrue(jsonFile.exists());

        MockAddressFactory addressFactory = new MockAddressFactory();
        SvdMemoryMapParser parser = new SvdMemoryMapParser(addressFactory);

        List<MemoryRegion> regions = parser.parseJson(jsonFile);

        // Find Ethernet regions
        List<MemoryRegion> ethRegions = regions.stream()
                .filter(r -> r.getPeripheralClass() == MemoryRegion.PeripheralClass.ETHERNET_MAC)
                .toList();

        assertEquals(1, ethRegions.size(), "Should find ETH_MAC");
        assertEquals("ETH_MAC", ethRegions.get(0).getName());
    }

    @Test
    void testParseJsonCategorizesByType() throws Exception {
        File jsonFile = new File(TEST_JSON_PATH);
        assertTrue(jsonFile.exists());

        MockAddressFactory addressFactory = new MockAddressFactory();
        SvdMemoryMapParser parser = new SvdMemoryMapParser(addressFactory);

        List<MemoryRegion> regions = parser.parseJson(jsonFile);

        // Check region types are correctly parsed
        long flashCount = regions.stream()
                .filter(r -> r.getRegionType() == MemoryRegion.RegionType.FLASH_ROM)
                .count();
        long sramCount = regions.stream()
                .filter(r -> r.getRegionType() == MemoryRegion.RegionType.INTERNAL_SRAM)
                .count();
        long mmioCount = regions.stream()
                .filter(r -> r.getRegionType() == MemoryRegion.RegionType.MMIO_PERIPHERAL)
                .count();

        assertEquals(1, flashCount, "Should have 1 Flash region");
        assertEquals(3, sramCount, "Should have 3 SRAM regions (SRAM1/2/CCM)");
        assertTrue(mmioCount > 25, "Should have many MMIO peripherals");
    }

    @Test
    void testParseJsonVolatilitySet() throws Exception {
        File jsonFile = new File(TEST_JSON_PATH);
        assertTrue(jsonFile.exists());

        MockAddressFactory addressFactory = new MockAddressFactory();
        SvdMemoryMapParser parser = new SvdMemoryMapParser(addressFactory);

        List<MemoryRegion> regions = parser.parseJson(jsonFile);

        // MMIO should be volatile, SRAM should not be
        MemoryRegion uart = regions.stream()
                .filter(r -> r.getName().equals("USART1"))
                .findFirst().orElse(null);
        assertNotNull(uart);
        assertTrue(uart.isVolatile(), "UART should be volatile");

        MemoryRegion sram = regions.stream()
                .filter(r -> r.getName().equals("SRAM1"))
                .findFirst().orElse(null);
        assertNotNull(sram);
        assertFalse(sram.isVolatile(), "SRAM should not be volatile");
    }

    @Test
    void testInputSourceMapping() throws Exception {
        File jsonFile = new File(TEST_JSON_PATH);
        assertTrue(jsonFile.exists());

        MockAddressFactory addressFactory = new MockAddressFactory();
        SvdMemoryMapParser parser = new SvdMemoryMapParser(addressFactory);

        List<MemoryRegion> regions = parser.parseJson(jsonFile);

        // Test that memory regions map to correct input source types
        MemoryRegion adc = regions.stream()
                .filter(r -> r.getName().equals("ADC1"))
                .findFirst().orElse(null);
        assertNotNull(adc);
        assertEquals(InputSource.SourceType.SENSOR_ADC, adc.toInputSourceType());

        MemoryRegion uart = regions.stream()
                .filter(r -> r.getName().equals("USART1"))
                .findFirst().orElse(null);
        assertNotNull(uart);
        assertEquals(InputSource.SourceType.NETWORK_COMMS, uart.toInputSourceType());

        MemoryRegion timer = regions.stream()
                .filter(r -> r.getName().equals("TIM1"))
                .findFirst().orElse(null);
        assertNotNull(timer);
        assertEquals(InputSource.SourceType.CONSTANT, timer.toInputSourceType());
    }
}
