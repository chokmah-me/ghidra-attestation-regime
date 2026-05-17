// MemoryRegion.java
// Annotated memory region from SVD or manual JSON map

package chokmah.plugin.attestation.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;

/**
 * A named memory region with attestation-relevant categorization.
 * Parsed from SVD file or manual JSON memory map annotation.
 *
 * Standard ARM Cortex-M heuristic ranges (no SVD):
 *   0x40000000-0x5FFFFFFF = MMIO (peripheral)
 *   0x20000000-0x3FFFFFFF = internal SRAM
 *   0x60000000+           = external memory
 * ~70% correct on standard Cortex-M targets.
 */
public class MemoryRegion {

    public enum RegionType {
        FLASH_ROM,           // Code and read-only data -> neutral
        INTERNAL_SRAM,       // Read-write data, stack, heap -> internal state
        MMIO_PERIPHERAL,     // Device registers -> classify by peripheral type
        EXTERNAL_RAM,        // Off-chip memory -> conservative external
        UNKNOWN              // No annotation -> conservative Regime 3a
    }

    public enum PeripheralClass {
        NONE,                // Not a peripheral region
        ADC,                 // Analog-to-digital converter -> Regime 2
        SPI,                 // SPI controller -> depends on attached device
        I2C,                 // I2C controller -> depends on attached device
        UART,                // Serial comms -> Regime 3a
        ETHERNET_MAC,        // Network interface -> Regime 3a
        USB,                 // USB controller -> Regime 3a
        CAN,                 // CAN bus -> Regime 3a (industrial network)
        FIELDBUS,            // Industrial field bus (Profibus, EtherNet/IP, Modbus) -> Regime 3a
        TIMERS_PWM,          // Internal timing -> Regime 1
        GPIO,                // General purpose I/O -> depends on pin function
        DMA,                 // Direct memory access -> internal
        WATCHDOG,            // Safety-critical internal -> Regime 1
        CRYPTO_ACCEL,        // AES/SHA hardware accelerator -> Regime 1
        UNKNOWN_PERIPHERAL   // Unclassified MMIO -> conservative Regime 3a
    }

    private final String name;
    private final AddressRange addressRange;
    private final RegionType regionType;
    private final PeripheralClass peripheralClass;
    private final boolean isVolatile;

    public MemoryRegion(String name, Address start, Address end,
                        RegionType regionType, PeripheralClass peripheralClass,
                        boolean isVolatile) {
        this.name = name;
        this.addressRange = (start != null && end != null) ? new AddressRangeImpl(start, end) : null;
        this.regionType = regionType;
        this.peripheralClass = peripheralClass;
        this.isVolatile = isVolatile;
    }

    public String getName() {
        return name;
    }

    public AddressRange getAddressRange() {
        return addressRange;
    }

    public RegionType getRegionType() {
        return regionType;
    }

    public PeripheralClass getPeripheralClass() {
        return peripheralClass;
    }

    public boolean isVolatile() {
        return isVolatile;
    }

    public boolean contains(Address addr) {
        return addressRange != null && addressRange.contains(addr);
    }

    /**
     * Maps this memory region to default input source type for attestation.
     * KEY: network/comms peripherals -> Regime 3a. Sensors -> Regime 2.
     */
    public InputSource.SourceType toInputSourceType() {
        return switch (regionType) {
            case FLASH_ROM -> InputSource.SourceType.CONSTANT;
            case INTERNAL_SRAM -> InputSource.SourceType.INTERNAL_STATE;
            case EXTERNAL_RAM -> InputSource.SourceType.UNCLASSIFIED_EXT;
            case UNKNOWN -> InputSource.SourceType.UNCLASSIFIED_EXT;
            case MMIO_PERIPHERAL -> switch (peripheralClass) {
                case ADC, GPIO -> InputSource.SourceType.SENSOR_ADC;
                case UART, ETHERNET_MAC, USB, CAN -> InputSource.SourceType.NETWORK_COMMS;
                case FIELDBUS -> InputSource.SourceType.FIELDBUS;
                case SPI, I2C -> InputSource.SourceType.SENSOR_ADC; // heuristic: often sensors
                case UNKNOWN_PERIPHERAL -> InputSource.SourceType.MMIO_UNKNOWN;
                default -> InputSource.SourceType.CONSTANT; // timers, watchdog, crypto
            };
        };
    }

    @Override
    public String toString() {
        String range = addressRange != null
                ? addressRange.getMinAddress() + "-" + addressRange.getMaxAddress()
                : "no-range";
        return String.format("%s [%s] type=%s periph=%s volatile=%s",
                name, range, regionType, peripheralClass, isVolatile);
    }
}
