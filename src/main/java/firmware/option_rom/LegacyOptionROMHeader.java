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
import ghidra.util.exception.DuplicateNameException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Formatter;

public class LegacyOptionROMHeader extends OptionROMHeader {
	// Original header fields
	private byte imageSize;
	private byte[] entryPointInstruction;

	private short entryPointOffset;
	private byte[] x86Image;

	public LegacyOptionROMHeader(BinaryReader reader) throws IOException {
		super(reader);
		reader.setPointerIndex(0x2);
		imageSize = reader.readNextByte();
		entryPointInstruction = reader.readNextByteArray(3);

		// The entry point field usually contains a relative JMP instruction. Decode it to find the
		// address of the entry point.
		entryPointOffset = 0x3;
		int executableSize;
		if (entryPointInstruction[0] == (byte) 0xEB) {
			entryPointOffset += entryPointInstruction[1];
			entryPointOffset += 0x2;
			executableSize = imageSize * OptionROMConstants.ROM_SIZE_UNIT - entryPointOffset;
		} else if (entryPointInstruction[0] == (byte) 0xE9) {
			entryPointOffset +=
					(short) (entryPointInstruction[2] << 8 | entryPointInstruction[1] & 0xFF);
			entryPointOffset += 0x3;
			executableSize = imageSize * OptionROMConstants.ROM_SIZE_UNIT - entryPointOffset;
		} else {
			executableSize = imageSize * OptionROMConstants.ROM_SIZE_UNIT - 0x3;
		}

		reader.setPointerIndex(entryPointOffset);
		x86Image = reader.readNextByteArray(executableSize);
	}

	@Override
	public ByteArrayInputStream getImageStream() {
		return new ByteArrayInputStream(x86Image);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("x86_option_rom_header", 0);
		structure.add(WORD, "signature", null);
		structure.add(BYTE, "image_size", null);
		structure.add(new ArrayDataType(BYTE, 0x3, BYTE.getLength()), "entry_point_instruction", null);
		structure.add(new ArrayDataType(BYTE, 0x12, BYTE.getLength()), "reserved", null);
		structure.add(WORD, "pcir_offset", null);
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
