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
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.IOException;

/**
 * Parser for the PCI data structure stored within PCI option ROM images. See OptionROMHeader for a
 * description of the fields within the data structure.
 */
public class PCIDataStructureHeader implements StructConverter {
	// Original header fields
	private final String signature;
	private final short vendorID;
	private final short deviceID;
	private final short deviceListOffset;
	private final short headerSize;
	private final short headerRevision;
	private final byte[] classCode;
	private final short imageLength;
	private final short romRevision;
	private final byte codeType;
	private final byte lastImageIndicator;
	private final short maxRuntimeSize;
	private final short configUtilityCodeOffset;
	private final short dmtfClpOffset;

	/**
	 * Constructs a PCIDataStructureHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
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

	/**
	 * Returns the current image's code type.
	 *
	 * @return the current image's code type
	 */
	public byte getCodeType() {
		return codeType;
	}

	/**
	 * Returns the device list offset.
	 *
	 * @return the device list offset
	 */
	public short getDeviceListOffset() {
		if (headerRevision == 3) {
			return deviceListOffset;
		} else {
			return 0;
		}
	}

	/**
	 * Returns the size of the current image.
	 *
	 * @return the size of the current image
	 */
	public int getImageLength() {
		return imageLength * OptionROMConstants.ROM_SIZE_UNIT;
	}

	/**
	 * Checks if this is the last image in the expansion ROM.
	 *
	 * @return if this is the last image in the expansion ROM
	 */
	public boolean isLastImage() {
		// Bit 7 in the last image indicator field tells if this is the last image in the ROM.
		return (lastImageIndicator & 0x80) != 0;
	}

	/**
	 * Returns FileAttributes for the current image.
	 *
	 * @return FileAttributes for the current image
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add(FileAttributeType.SIZE_ATTR, Long.valueOf(getImageLength()));
		attributes.add("Vendor ID", String.format("%#x", vendorID));
		attributes.add("Device ID", String.format("%#x", deviceID));
		attributes.add("Vendor ROM Revision", romRevision);
		attributes.add("Code Type", OptionROMConstants.CodeType.toString(codeType));
		return attributes;
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("pci_data_structure_header_t", 0);
		structure.add(new ArrayDataType(ASCII, OptionROMConstants.PCIR_SIGNATURE.length(), 1),
				"signature", null);
		structure.add(WORD, 2, "vendor_id", null);
		structure.add(WORD, 2, "device_id", null);
		if (headerRevision == 3) {
			structure.add(WORD, 2, "device_list_offset", null);
		} else {
			structure.add(WORD, 2, "reserved_1", null);
		}

		structure.add(WORD, 2, "pcir_header_len", null);
		structure.add(BYTE, 1, "pcir_header_rev", null);
		structure.add(new ArrayDataType(BYTE, 3, 1), "class_code", null);
		structure.add(WORD, 2, "image_len", null);
		structure.add(WORD, 2, "vendor_rom_rev", null);
		structure.add(BYTE, 1, "code_type", null);
		structure.add(BYTE, 1, "last_image_indicator", null);
		if (headerRevision == 3) {
			structure.add(WORD, 2, "max_runtime_image_len", null);
			structure.add(WORD, 2, "config_utility_code_offset", null);
			structure.add(WORD, 2, "dmtf_clp_entry_point_offset", null);
		} else {
			structure.add(WORD, "reserved_2", null);
		}

		return structure;
	}
}
