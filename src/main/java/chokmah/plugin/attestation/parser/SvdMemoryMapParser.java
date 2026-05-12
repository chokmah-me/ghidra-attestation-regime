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

    private final Program program;

    public SvdMemoryMapParser(Program program) {
        this.program = program;
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

            Address startAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(baseAddr);
            Address endAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(baseAddr + size - 1);

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
        // TODO: implement JSON parsing using Jackson or javax.json
        // For now: return empty list to trigger heuristic fallback
        return Collections.emptyList();
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
        // Calculate size from highest register offset + register size
        // TODO: proper implementation
        return 0x1000;
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
