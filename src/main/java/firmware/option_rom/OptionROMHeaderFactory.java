/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package firmware.option_rom;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

/**
 * Factory for constructing the correct option ROM type based off the code type field in the PCI
 * data structure header.
 */
public class OptionROMHeaderFactory {
	private OptionROMHeaderFactory() {}

	/**
	 * Constructs an OptionROMHeader from a specified BinaryReader by checking the code type field
	 * in the PCI data structure header.
	 *
	 * @param reader the specified BinaryReader
	 * @return       the parsed OptionROMHeader
	 */
	public static OptionROMHeader parseOptionROM(BinaryReader reader) throws IOException {
		short signature = reader.readNextShort();
		if (signature != OptionROMConstants.ROM_SIGNATURE) {
			throw new IOException("Not a valid PCI option ROM header");
		}

		// Read the PCI data structure offset field in the ROM header.
		reader.setPointerIndex(0x18);
		short pcirOffset = reader.readNextShort();

		// Read the code type field in the PCI data structure.
		reader.setPointerIndex(pcirOffset + 0x14);
		byte codeType = reader.readNextByte();

		// Construct the correct OptionROMHeader based off the code type.
		reader.setPointerIndex(0);
		switch (codeType) {
			case OptionROMConstants.CodeType.PC_AT_COMPATIBLE:
				return new LegacyOptionROMHeader(reader);
			case OptionROMConstants.CodeType.EFI:
				return new UEFIOptionROMHeader(reader);
			default:
				return new OptionROMHeader(reader);
		}
	}
}
