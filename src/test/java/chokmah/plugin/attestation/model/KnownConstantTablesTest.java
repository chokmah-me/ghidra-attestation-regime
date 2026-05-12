package chokmah.plugin.attestation.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KnownConstantTablesTest {

    @Test
    void testIdentifyTableAesSbox() {
        byte[] aesSbox = new byte[256];
        aesSbox[0] = (byte) 0x63;

        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(aesSbox, 1);
        assertNotNull(match);
        assertEquals("AES S-box", match.name());
        assertEquals(256, match.expectedSizeBytes());
    }

    @Test
    void testIdentifyTableAesSboxWrongPrefix() {
        byte[] data = new byte[256];
        data[0] = (byte) 0x99; // wrong prefix

        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(data, 1);
        assertNull(match);
    }

    @Test
    void testIdentifyTableCrc32Ieee() {
        byte[] crc32 = new byte[1024];
        crc32[0] = 0;
        crc32[1] = 0;
        crc32[2] = 0;
        crc32[3] = 0;

        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(crc32, 4);
        assertNotNull(match);
        assertEquals("CRC-32 IEEE 802.3", match.name());
        assertEquals(1024, match.expectedSizeBytes());
    }

    @Test
    void testIdentifyTableCrc16Modbus() {
        byte[] crc16 = new byte[512];
        crc16[0] = 0;
        crc16[1] = 0;

        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(crc16, 2);
        assertNotNull(match);
        assertEquals("CRC-16 Modbus", match.name());
    }

    @Test
    void testIdentifyTableSha256H0() {
        byte[] sha256h0 = new byte[32];
        sha256h0[0] = (byte) 0x67;
        sha256h0[1] = (byte) 0xe6;
        sha256h0[2] = (byte) 0x09;
        sha256h0[3] = (byte) 0x6a;

        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(sha256h0, 4);
        assertNotNull(match);
        assertEquals("SHA-256 H(0)", match.name());
    }

    @Test
    void testIdentifyTableNull() {
        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(null, 1);
        assertNull(match);
    }

    @Test
    void testIdentifyTableTooShort() {
        byte[] data = new byte[3];
        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(data, 1);
        assertNull(match);
    }

    @Test
    void testIdentifyTableNoMatchingSize() {
        byte[] data = new byte[512]; // CRC-32 is 1024, CRC-16 is 512
        data[0] = 0;
        data[1] = 0;
        data[2] = 0;
        data[3] = 0;

        // Size 512 with CRC-32 prefix doesn't match any known table
        KnownConstantTables.TableMatch match = KnownConstantTables.identifyTable(data, 4);
        assertNull(match);
    }

    @Test
    void testIsTableSizeSuspicious256Bytes1ByteEntries() {
        assertTrue(KnownConstantTables.isTableSizeSuspicious(256, 1));
    }

    @Test
    void testIsTableSizeSuspicious255Bytes1ByteEntries() {
        assertFalse(KnownConstantTables.isTableSizeSuspicious(255, 1));
    }

    @Test
    void testIsTableSizeSuspicious1024Bytes4ByteEntries() {
        assertTrue(KnownConstantTables.isTableSizeSuspicious(1024, 4));
    }

    @Test
    void testIsTableSizeSuspiciousLargeTable() {
        assertTrue(KnownConstantTables.isTableSizeSuspicious(10000, 1));
    }

    @Test
    void testIsTableSizeSuspiciousSmallTable() {
        assertFalse(KnownConstantTables.isTableSizeSuspicious(100, 1));
    }

    @Test
    void testIsTableSizeSuspiciousZeroEntrySize() {
        assertFalse(KnownConstantTables.isTableSizeSuspicious(256, 0));
    }

    @Test
    void testIsTableSizeSuspiciousNegativeEntrySize() {
        assertFalse(KnownConstantTables.isTableSizeSuspicious(256, -1));
    }

    @Test
    void testGetAllKnownTables() {
        var tables = KnownConstantTables.getAllKnownTables();
        assertFalse(tables.isEmpty());
        assertTrue(tables.stream().anyMatch(t -> "CRC-32 IEEE 802.3".equals(t.name())));
        assertTrue(tables.stream().anyMatch(t -> "AES S-box".equals(t.name())));
        assertTrue(tables.stream().anyMatch(t -> "SHA-256 H(0)".equals(t.name())));
    }

    @Test
    void testGetAllKnownTablesUnmodifiable() {
        var tables = KnownConstantTables.getAllKnownTables();
        assertThrows(UnsupportedOperationException.class, tables::clear);
    }
}
