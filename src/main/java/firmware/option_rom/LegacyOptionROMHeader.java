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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.IOException;
import java.util.Formatter;

/**
 * Parser for legacy x86/PC compatible option ROM images. There are additional fields in the ROM
 * header:
 *
 *   ROM Header
 *   +---------+-------------------------------------------+
 *   | Type    | Size | Description                        |
 *   +---------+-------------------------------------------+
 *   | u16     |    2 | Signature (0xAA55, little endian)  |
 *   | u8      |    1 | Image Size (in units of 512 bytes) |
 *   | u8[3]   |    3 | Entry Point                        |
 *   | u8[18]  |   18 | Reserved                           |
 *   | u16     |    2 | PCI Data Structure Offset          |
 *   +---------+-------------------------------------------+
 *
 * The Entry Point field in the ROM header usually contains a JMP (rel8 or rel16) instruction.
 */
public class LegacyOptionROMHeader extends OptionROMHeader {
	// Original header fields
	private byte imageSize;
	private byte[] entryPointInstruction;

	private int entryPointOffset;

	/**
	 * Constructs a LegacyOptionROMHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public LegacyOptionROMHeader(BinaryReader reader) throws IOException {
		super(reader);
		byte codeType = getPCIRHeader().getCodeType();
		if (codeType != OptionROMConstants.CodeType.PC_AT_COMPATIBLE) {
			throw new IOException("Code type mismatch: expected PC-AT compatible (0), got " +
					OptionROMConstants.CodeType.toString(codeType) + " (" + codeType + ')');
		}

		reader.setPointerIndex(0x2);
		imageSize = reader.readNextByte();
		entryPointInstruction = reader.readNextByteArray(3);

		// The entry point field usually contains a relative JMP instruction. Decode it to find the
		// address of the entry point.
		entryPointOffset = 0x3;
		if (entryPointInstruction[0] == (byte) 0xEB) {
			// JMP rel8 (relative to next instruction)
			entryPointOffset += entryPointInstruction[1];
			entryPointOffset += 0x2; // Size of the instruction (offset to next instruction)
		} else if (entryPointInstruction[0] == (byte) 0xE9) {
			// JMP rel16 (relative to next instruction)
			entryPointOffset += (short)
					(entryPointInstruction[2] << 8 | entryPointInstruction[1] & 0xFF) & 0xFFFF;
			entryPointOffset += 0x3; // Size of the instruction (offset to next instruction)
		}

		reader.setPointerIndex(0);
	}

	/**
	 * Returns the decoded entry point offset.
	 *
	 * @return the decoded entry point offset
	 */
	public int getEntryPointOffset() {
		return entryPointOffset;
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("x86_option_rom_header_t", 0);
		structure.add(WORD, 2, "signature", null);
		structure.add(BYTE, 1, "image_size", null);
		structure.add(new ArrayDataType(BYTE, 0x3, 1), "entry_point_instruction", null);
		structure.add(new ArrayDataType(BYTE, 0x12, 1), "reserved", null);
		structure.add(POINTER, 2, "pcir_offset", null);
		return structure;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("Entry Point Instruction: %02X %02X %02X\n", entryPointInstruction[0],
				entryPointInstruction[1], entryPointInstruction[2]);
		formatter.format("Decoded Entry Point Address: 0x%X\n", entryPointOffset);
		formatter.format("%s\n", super.toString());
		return formatter.toString();
	}
}
