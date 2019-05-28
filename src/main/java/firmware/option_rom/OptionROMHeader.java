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
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Formatter;

public class OptionROMHeader implements StructConverter {
	// Original header fields
	private short signature;
	private short pcirOffset;

	private PCIDataStructureHeader pcirHeader;
	private byte[] rawImage;

	public OptionROMHeader(BinaryReader reader) throws IOException {
		signature = reader.readNextShort();
		if (signature != OptionROMConstants.ROM_SIGNATURE) {
			throw new IOException("Not a valid PCI option ROM");
		}

		// Read the PCI data structure header.
		reader.setPointerIndex(0x18);
		pcirOffset = reader.readNextShort();
		reader.setPointerIndex(pcirOffset);
		pcirHeader = new PCIDataStructureHeader(reader);

		reader.setPointerIndex(0);
		rawImage = reader.readNextByteArray(pcirHeader.getImageLength());
	}

	public ByteArrayInputStream getImageStream() {
		// For a generic option ROM with an unknown code type, just return the entire ROM as the
		// image. This will be overridden by subclasses (UEFIOptionROMHeader, etc) to only return
		// the executable.
		return new ByteArrayInputStream(rawImage);
	}

	public PCIDataStructureHeader getPCIRHeader() {
		return pcirHeader;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("option_rom_header", 0);
		structure.add(WORD, "signature", null);
		structure.add(new ArrayDataType(BYTE, 0x16, BYTE.getLength()), "reserved", null);
		structure.add(WORD, "pcir_offset", null);
		return structure;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("PCI Data Structure Offset: 0x%X\n", pcirOffset);
		formatter.format("%s\n", pcirHeader.toString());
		return formatter.toString();
	}
}
