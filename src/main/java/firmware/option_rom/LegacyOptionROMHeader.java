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
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;

import java.io.IOException;

/**
 * Parser for legacy x86/PC compatible option ROM images. There are additional fields in the ROM
 * header:
 *
 * <pre>
 *   ROM Header
 *   +---------+------+------------------------------------+
 *   | Type    | Size | Description                        |
 *   +---------+------+------------------------------------+
 *   | u16     |    2 | Signature (0xAA55, little endian)  |
 *   | u8      |    1 | Image Size (in units of 512 bytes) |
 *   | u8[3]   |    3 | Entry Point                        |
 *   | u8[18]  |   18 | Reserved                           |
 *   | u16     |    2 | PCI Data Structure Offset          |
 *   +---------+------+------------------------------------+
 * </pre>
 *
 * The Entry Point field in the ROM header usually contains a JMP (rel8 or rel16) instruction.
 */
public class LegacyOptionROMHeader extends OptionROMHeader {
	// Original header fields
	private final byte imageSize;
	private final byte[] entryPointInstruction;

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

		// The entry point field usually contains a relative CALL or JMP instruction. Decode it to find the address of
		// the entry point.
		entryPointOffset = 0x3;
		if (entryPointInstruction[0] == (byte) 0xE8) {
			// CALL rel16 (relative to next instruction)
			entryPointOffset += ((entryPointInstruction[2] & 0xFF) << 8 | entryPointInstruction[1] & 0xFF) & 0xFFFF;
			entryPointOffset += 0x3; // Size of the instruction (offset to next instruction)
		}
		else if (entryPointInstruction[0] == (byte) 0xEB) {
			// JMP rel8 (relative to next instruction)
			entryPointOffset += entryPointInstruction[1] & 0xFF;
			entryPointOffset += 0x2; // Size of the instruction (offset to next instruction)
		}
		else if (entryPointInstruction[0] == (byte) 0xE9) {
			// JMP rel16 (relative to next instruction)
			entryPointOffset += ((entryPointInstruction[2] & 0xFF) << 8 | entryPointInstruction[1] & 0xFF) & 0xFFFF;
			entryPointOffset += 0x3; // Size of the instruction (offset to next instruction)
		}

		Msg.debug(this, String.format("Entry point instruction: %x %x %x", entryPointInstruction[0],
				entryPointInstruction[1], entryPointInstruction[2]));
		Msg.debug(this, String.format("Entry point offset: %#x", entryPointOffset));

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

	/**
	 * Returns FileAttributes for the current image.
	 *
	 * @return FileAttributes for the current image
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = super.getFileAttributes();
		attributes.add("Entry Point Instruction", String.format("%02X %02X %02X", entryPointInstruction[0],
				entryPointInstruction[1], entryPointInstruction[2]));
		attributes.add("Decoded Entry Point Address", String.format("%#x", entryPointOffset));
		return attributes;
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
}
