// KnownConstantTables.java
// Database of known-good constant tables for provenance checking (Regime 3b)
//
// Rationale: Large lookup tables are ubiquitous in embedded code (CRC tables,
// trig tables, thermocouple linearization). Flagging all as supply-chain risks
// drowns the analyst. This database allows the plugin to match table contents
// against known standards and reclassify verified tables to Regime 1 or 2.
//
// The final 3b call remains human. The plugin assists, does not decide.

package chokmah.plugin.attestation.model;

import java.util.*;

/**
 * Registry of known constant tables with their expected byte patterns.
 * Used in Step 3 (ComplexityAnalyzer) to match discovered tables against
 * known standards. A match means the table has explained provenance and
// is not a supply-chain flag.
 */
public class KnownConstantTables {

    public record TableMatch(String name, String standard, int expectedSizeBytes,
                             TableType tableType, byte[] expectedPrefix) {
    }

    public enum TableType {
        CRC_POLYNOMIAL,
        MATH_TRIG,
        THERMOCOUPLE_LINEARIZATION,
        IEEE_754_SPECIAL,
        S_BOX,
        PERMUTATION,
        MODBUS_CRC,
        ETHERNET_CRC,
        CUSTOM_HASH
    }

    private static final List<TableMatch> KNOWN_TABLES = new ArrayList<>();

    static {
        // CRC-32 IEEE 802.3 lookup table (256 entries, 4 bytes each = 1024 bytes)
        // First 4 bytes: 0x00000000 (little-endian: 00 00 00 00)
        // Entries at offset: known polynomial-dependent values
        KNOWN_TABLES.add(new TableMatch(
                "CRC-32 IEEE 802.3", "IEEE 802.3 / Ethernet",
                1024, TableType.CRC_POLYNOMIAL,
                new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00}
        ));

        // CRC-16 Modbus lookup table (256 entries, 2 bytes each = 512 bytes)
        KNOWN_TABLES.add(new TableMatch(
                "CRC-16 Modbus", "Modbus RTU/TCP",
                512, TableType.MODBUS_CRC,
                new byte[]{(byte) 0x00, (byte) 0x00}
        ));

        // CRC-8 (SMBus/MAXIM) lookup table (256 entries, 1 byte each = 256 bytes)
        KNOWN_TABLES.add(new TableMatch(
                "CRC-8 SMBus/MAXIM", "SMBus Specification",
                256, TableType.CRC_POLYNOMIAL,
                new byte[]{0x00}
        ));

        // AES S-box (256 entries, 1 byte each = 256 bytes)
        // First entry: 0x63
        KNOWN_TABLES.add(new TableMatch(
                "AES S-box", "FIPS-197",
                256, TableType.S_BOX,
                new byte[]{(byte) 0x63}
        ));

        // AES Inv S-box (256 entries, 1 byte each = 256 bytes)
        // First entry: 0x52
        KNOWN_TABLES.add(new TableMatch(
                "AES Inverse S-box", "FIPS-197",
                256, TableType.S_BOX,
                new byte[]{(byte) 0x52}
        ));

        // SHA-256 initial hash values (8 x 4 bytes = 32 bytes) - not a table but constant
        // h0 = 0x6a09e667
        KNOWN_TABLES.add(new TableMatch(
                "SHA-256 H(0)", "FIPS-180-4",
                32, TableType.CUSTOM_HASH,
                new byte[]{(byte) 0x67, (byte) 0xe6, (byte) 0x09, (byte) 0x6a}
        ));

        // SHA-256 round constants (64 x 4 bytes = 256 bytes)
        // K[0] = 0x428a2f98
        KNOWN_TABLES.add(new TableMatch(
                "SHA-256 K constants", "FIPS-180-4",
                256, TableType.CUSTOM_HASH,
                new byte[]{(byte) 0x98, (byte) 0x2f, (byte) 0x8a, (byte) 0x42}
        ));
    }

    /**
     * Attempt to match a discovered constant table against known standards.
     * Returns the best match or null if no known table matches.
     *
     * @param tableData  byte content of the discovered table
     * @param entrySize  size of each entry in bytes
     * @return TableMatch if known, null if unexplained
     */
    public static TableMatch identifyTable(byte[] tableData, int entrySize) {
        if (tableData == null || tableData.length < 4) {
            return null;
        }

        int tableSize = tableData.length;

        for (TableMatch candidate : KNOWN_TABLES) {
            if (tableSize == candidate.expectedSizeBytes) {
                boolean prefixMatch = true;
                byte[] prefix = candidate.expectedPrefix;
                for (int i = 0; i < prefix.length && i < tableData.length; i++) {
                    if (tableData[i] != prefix[i]) {
                        prefixMatch = false;
                        break;
                    }
                }
                if (prefixMatch) {
                    // TODO: deeper verification (sample additional entries)
                    return candidate;
                }
            }
        }

        return null;  // unexplained table -> provenance check flag
    }

    /**
     * True if the table size suggests a lookup table worth investigating.
     * Threshold: >= 256 entries (configurable).
     */
    public static boolean isTableSizeSuspicious(int totalBytes, int entrySize) {
        if (entrySize <= 0) return false;
        int entries = totalBytes / entrySize;
        return entries >= 256;
    }

    public static List<TableMatch> getAllKnownTables() {
        return Collections.unmodifiableList(KNOWN_TABLES);
    }
}
