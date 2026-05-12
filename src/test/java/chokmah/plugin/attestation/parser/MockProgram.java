package chokmah.plugin.attestation.parser;

import ghidra.program.model.address.GenericAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;

/**
 * Simple factory for creating an AddressFactory for testing.
 */
class MockAddressFactory {
    public static GenericAddressFactory create() {
        GenericAddressSpace defaultSpace = new GenericAddressSpace("ram", 32, 0);
        return new GenericAddressFactory(new GenericAddressSpace[]{defaultSpace});
    }
}
