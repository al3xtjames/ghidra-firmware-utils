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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.Formatter;

public class PCIDataStructureHeader implements StructConverter {
	// Original header fields
	private String signature;
	private short vendorID;
	private short deviceID;
	private short deviceListOffset;
	private short headerSize;
	private short headerRevision;
	private byte[] classCode;
	private short imageLength;
	private short romRevision;
	private byte codeType;
	private byte lastImageIndicator;
	private short maxRuntimeSize;
	private short configUtilityCodeOffset;
	private short dmtfClpOffset;

	public PCIDataStructureHeader(BinaryReader reader) throws IOException {
		signature = reader.readNextAsciiString(OptionROMConstants.PCIR_SIGNATURE.length());
		if (!signature.equals(OptionROMConstants.PCIR_SIGNATURE)) {
			throw new IOException("Not a valid PCI data structure header");
		}

		vendorID = reader.readNextShort();
		deviceID = reader.readNextShort();
		deviceListOffset = reader.readNextShort();
		headerSize = reader.readNextShort();
		headerRevision = reader.readNextByte();
		classCode = reader.readNextByteArray(3);
		imageLength = reader.readNextShort();
		romRevision = reader.readNextShort();
		codeType = reader.readNextByte();
		lastImageIndicator = reader.readNextByte();
		if (headerRevision == 3) {
			maxRuntimeSize = reader.readNextShort();
			configUtilityCodeOffset = reader.readNextShort();
			dmtfClpOffset = reader.readNextShort();
		} else {
			maxRuntimeSize = 0;
			configUtilityCodeOffset = 0;
			dmtfClpOffset = 0;
		}
	}

	public int getImageLength() {
		return imageLength * OptionROMConstants.ROM_SIZE_UNIT;
	}

	public byte getCodeType() {
		return codeType;
	}

	public boolean isLastImage() {
		// Bit 7 in the last image indicator field tells if this is the last image in the ROM.
		return (lastImageIndicator & 0x80) != 0;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("pcir", 0);
		structure.add(DWORD, 0);
		return structure;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("Vendor ID: 0x%X\n", vendorID);
		formatter.format("Device ID: 0x%X\n", deviceID);
		formatter.format("Image Length: 0x%X\n", getImageLength());
		formatter.format("Vendor ROM Revison: 0x%X\n", romRevision);
		formatter.format("Code Type: %s (%d)\n", OptionROMConstants.CodeType.toString(codeType),
				codeType);
		formatter.format("Last Image: %b\n", isLastImage());
		return formatter.toString();
	}
}
