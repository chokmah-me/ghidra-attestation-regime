// SvdMemoryMapParser.java
// Parse ARM CMSIS-SVD files to produce MemoryRegion annotations
//
// SVD files describe the complete memory and register map of ARM Cortex-M
// microcontrollers. Parsing them yields precise peripheral type information
// needed for input source classification (sensor vs network vs internal).
//
// Requires: SVD file from vendor or CMSIS-SVD repository
//           (https://github.com/posborne/cmsis-svd)
//
// Falls back to heuristic Cortex-M memory map if no SVD available.

package chokmah.plugin.attestation.parser;

import chokmah.plugin.attestation.model.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import org.w3c.dom.*;

import javax.xml.parsers.*;
import java.io.*;
import java.util.*;

/**
 * Parses CMSIS-SVD XML files to extract memory regions and peripheral
// classifications for the InputSourceTagger.
 */
public class SvdMemoryMapParser {

    private final AddressFactory addressFactory;

    public SvdMemoryMapParser(Program program) {
        this.addressFactory = program.getAddressFactory();
    }

    public SvdMemoryMapParser(AddressFactory addressFactory) {
        this.addressFactory = addressFactory;
    }

    /**
     * Parse an SVD XML file into a list of MemoryRegions.
     *
     * @param svdFile path to CMSIS-SVD XML file
     * @return list of classified memory regions
     */
    public List<MemoryRegion> parseSvd(File svdFile) throws Exception {
        List<MemoryRegion> regions = new ArrayList<>();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(svdFile);
        doc.getDocumentElement().normalize();

        // Parse device-level memory regions
        NodeList peripherals = doc.getElementsByTagName("peripheral");
        for (int i = 0; i < peripherals.getLength(); i++) {
            Element peripheral = (Element) peripherals.item(i);

            String name = getTextContent(peripheral, "name", "UNKNOWN");
            String baseAddrStr = getTextContent(peripheral, "baseAddress", "0");
            long baseAddr = Long.parseLong(baseAddrStr.replace("0x", ""), 16);

            // Determine peripheral size
            long size = 0x1000;  // default 4KB
            NodeList registers = peripheral.getElementsByTagName("register");
            if (registers.getLength() > 0) {
                size = computePeripheralSize(peripheral, baseAddr);
            }

            Address startAddr = addressFactory.getDefaultAddressSpace().getAddress(baseAddr);
            Address endAddr = addressFactory.getDefaultAddressSpace().getAddress(baseAddr + size - 1);

            MemoryRegion.PeripheralClass pClass = classifyPeripheral(name, peripheral);
            boolean isVolatile = true;  // all MMIO is volatile

            regions.add(new MemoryRegion(
                    name, startAddr, endAddr,
                    MemoryRegion.RegionType.MMIO_PERIPHERAL,
                    pClass, isVolatile
            ));
        }

        return regions;
    }

    /**
     * Parse a manual JSON memory map (for cases without SVD).
     * JSON format:
     * {
     *   "regions": [
     *     {
     *       "name": "USART1",
     *       "start": "0x40011000",
     *       "end": "0x400113FF",
     *       "type": "MMIO_PERIPHERAL",
     *       "peripheral_class": "UART",
     *       "volatile": true
     *     }
     *   ]
     * }
     */
    public List<MemoryRegion> parseJson(File jsonFile) throws Exception {
        List<MemoryRegion> regions = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(jsonFile);
        JsonNode regionsNode = root.get("regions");

        if (regionsNode == null || !regionsNode.isArray()) {
            return regions;
        }

        for (JsonNode regionNode : regionsNode) {
            String name = getJsonString(regionNode, "name", "UNKNOWN");
            String startStr = getJsonString(regionNode, "start", "0x0");
            String endStr = getJsonString(regionNode, "end", "0x0");
            String typeStr = getJsonString(regionNode, "type", "UNKNOWN");
            String classStr = getJsonString(regionNode, "peripheral_class", "NONE");
            boolean isVolatile = getJsonBoolean(regionNode, "volatile", true);

            long startAddr = parseHex(startStr);
            long endAddr = parseHex(endStr);

            Address start = addressFactory.getDefaultAddressSpace().getAddress(startAddr);
            Address end = addressFactory.getDefaultAddressSpace().getAddress(endAddr);

            MemoryRegion.RegionType regionType = parseRegionType(typeStr);
            MemoryRegion.PeripheralClass peripheralClass = parsePeripheralClass(classStr);

            regions.add(new MemoryRegion(name, start, end, regionType, peripheralClass, isVolatile));
        }

        return regions;
    }

    private long parseHex(String hexStr) {
        if (hexStr.startsWith("0x") || hexStr.startsWith("0X")) {
            return Long.parseLong(hexStr.substring(2), 16);
        }
        return Long.parseLong(hexStr, 16);
    }

    private String getJsonString(JsonNode node, String field, String defaultValue) {
        JsonNode fieldNode = node.get(field);
        return fieldNode != null && fieldNode.isTextual() ? fieldNode.asText() : defaultValue;
    }

    private boolean getJsonBoolean(JsonNode node, String field, boolean defaultValue) {
        JsonNode fieldNode = node.get(field);
        return fieldNode != null && fieldNode.isBoolean() ? fieldNode.asBoolean() : defaultValue;
    }

    private MemoryRegion.RegionType parseRegionType(String typeStr) {
        return switch (typeStr.toUpperCase()) {
            case "FLASH_ROM" -> MemoryRegion.RegionType.FLASH_ROM;
            case "INTERNAL_SRAM" -> MemoryRegion.RegionType.INTERNAL_SRAM;
            case "MMIO_PERIPHERAL" -> MemoryRegion.RegionType.MMIO_PERIPHERAL;
            case "EXTERNAL_RAM" -> MemoryRegion.RegionType.EXTERNAL_RAM;
            default -> MemoryRegion.RegionType.UNKNOWN;
        };
    }

    private MemoryRegion.PeripheralClass parsePeripheralClass(String classStr) {
        return switch (classStr.toUpperCase()) {
            case "ADC" -> MemoryRegion.PeripheralClass.ADC;
            case "SPI" -> MemoryRegion.PeripheralClass.SPI;
            case "I2C" -> MemoryRegion.PeripheralClass.I2C;
            case "UART" -> MemoryRegion.PeripheralClass.UART;
            case "ETHERNET_MAC" -> MemoryRegion.PeripheralClass.ETHERNET_MAC;
            case "USB" -> MemoryRegion.PeripheralClass.USB;
            case "CAN" -> MemoryRegion.PeripheralClass.CAN;
            case "TIMERS_PWM" -> MemoryRegion.PeripheralClass.TIMERS_PWM;
            case "GPIO" -> MemoryRegion.PeripheralClass.GPIO;
            case "DMA" -> MemoryRegion.PeripheralClass.DMA;
            case "WATCHDOG" -> MemoryRegion.PeripheralClass.WATCHDOG;
            case "CRYPTO_ACCEL" -> MemoryRegion.PeripheralClass.CRYPTO_ACCEL;
            case "NONE" -> MemoryRegion.PeripheralClass.NONE;
            default -> MemoryRegion.PeripheralClass.UNKNOWN_PERIPHERAL;
        };
    }

    /**
     * Classify a peripheral by name and description keywords.
     */
    private MemoryRegion.PeripheralClass classifyPeripheral(String name, Element peripheral) {
        String desc = getTextContent(peripheral, "description", "").toLowerCase();
        String fullText = (name + " " + desc).toLowerCase();

        // UART / USART
        if (matchesAny(fullText, "uart", "usart", "serial", "sci")) {
            return MemoryRegion.PeripheralClass.UART;
        }

        // Ethernet / MAC
        if (matchesAny(fullText, "ethernet", "eth_mac", "enet", "emac", "mac")) {
            return MemoryRegion.PeripheralClass.ETHERNET_MAC;
        }

        // USB
        if (matchesAny(fullText, "usb", "usb_otg", "usbd")) {
            return MemoryRegion.PeripheralClass.USB;
        }

        // CAN bus
        if (matchesAny(fullText, "can", "bxcan", "fdcan")) {
            return MemoryRegion.PeripheralClass.CAN;
        }

        // ADC
        if (matchesAny(fullText, "adc", "adcc", "sac")) {
            return MemoryRegion.PeripheralClass.ADC;
        }

        // SPI
        if (matchesAny(fullText, "spi", "qspi", "quadspi")) {
            return MemoryRegion.PeripheralClass.SPI;
        }

        // I2C
        if (matchesAny(fullText, "i2c", "twi", "smbus")) {
            return MemoryRegion.PeripheralClass.I2C;
        }

        // Timers / PWM
        if (matchesAny(fullText, "tim", "timer", "pwm", "lptim", "hrtim")) {
            return MemoryRegion.PeripheralClass.TIMERS_PWM;
        }

        // GPIO
        if (matchesAny(fullText, "gpio", "port", "pin")) {
            return MemoryRegion.PeripheralClass.GPIO;
        }

        // DMA
        if (matchesAny(fullText, "dma", "bdma", "mdma")) {
            return MemoryRegion.PeripheralClass.DMA;
        }

        // Watchdog
        if (matchesAny(fullText, "wwdg", "iwdg", "watchdog")) {
            return MemoryRegion.PeripheralClass.WATCHDOG;
        }

        // Crypto accelerator
        if (matchesAny(fullText, "aes", "hash", "cryp", "rng", "crc", "saes")) {
            return MemoryRegion.PeripheralClass.CRYPTO_ACCEL;
        }

        return MemoryRegion.PeripheralClass.UNKNOWN_PERIPHERAL;
    }

    private long computePeripheralSize(Element peripheral, long baseAddr) {
        long maxOffset = 0;
        NodeList registers = peripheral.getElementsByTagName("register");
        for (int i = 0; i < registers.getLength(); i++) {
            Element reg = (Element) registers.item(i);
            String offsetStr = getTextContent(reg, "addressOffset", "0");
            String sizeStr = getTextContent(reg, "size", "32");
            try {
                long offset = parseHexOrDec(offsetStr);
                long bits = Long.parseLong(sizeStr.replaceAll("[^0-9]", ""));
                long regEnd = offset + Math.max(bits / 8, 1);
                if (regEnd > maxOffset) maxOffset = regEnd;
            } catch (NumberFormatException ignored) { }
        }
        if (maxOffset == 0) return 0x1000;
        // round up to next power of two, minimum 0x400
        long size = Math.max(maxOffset, 0x400);
        long pow2 = 1;
        while (pow2 < size) pow2 <<= 1;
        return pow2;
    }

    private long parseHexOrDec(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) return Long.parseLong(s.substring(2), 16);
        return Long.parseLong(s);
    }

    private String getTextContent(Element parent, String tagName, String defaultValue) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0 && nodes.item(0).getTextContent() != null) {
            return nodes.item(0).getTextContent().trim();
        }
        return defaultValue;
    }

    private boolean matchesAny(String text, String... keywords) {
        for (String kw : keywords) {
            if (text.contains(kw)) return true;
        }
        return false;
    }
}
