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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Formatter;

/**
 * Common parser for PCI expansion ROMs.
 *
 * A PCI expansion ROM may contain more than one image. Each image will contain the following
 * structures:
 *
 *   ROM Header
 *   +---------+--------------------------------------------------------------------------+
 *   | Type    | Size | Description                                                       |
 *   +---------+--------------------------------------------------------------------------+
 *   | u16     |    2 | Signature (0xAA55, little endian)                                 |
 *   | u8[22]  |   22 | Reserved                                                          |
 *   | u16     |    2 | PCI Data Structure Offset                                         |
 *   +---------+--------------------------------------------------------------------------+
 *
 *   PCI Data Structure
 *   +---------+--------------------------------------------------------------------------+
 *   | Type    | Size | Description                                                       |
 *   +---------+--------------------------------------------------------------------------+
 *   | char[4] |    4 | Signature ("PCIR")                                                |
 *   | u16     |    2 | Vendor ID                                                         |
 *   | u16     |    2 | Device ID                                                         |
 *   | u16     |    2 | Device List Offset (only for rev 3, otherwise Reserved)           |
 *   | u16     |    2 | PCI Data Structure Size (bytes)                                   |
 *   | u8      |    1 | PCI Data Structure Revision                                       |
 *   | u24     |    3 | Class Code                                                        |
 *   | u16     |    2 | Image Length (in units of 512 bytes)                              |
 *   | u16     |    2 | Vendor ROM Revision                                               |
 *   | u8      |    1 | Code Type                                                         |
 *   | u8      |    1 | Last Image Indicator                                              |
 *   | u16     |    2 | Maximum Runtime Image Length (only for rev 3, otherwise Reserved) |
 *   | u16     |    2 | Configuration Utility Code Offset (only for rev 3)                |
 *   | u16     |    2 | DMTF CLP Entry Point Offset (only for rev 3)                      |
 *   +---------+--------------------------------------------------------------------------+
 *
 * The ROM header must begin at the start of the each image's address space. The PCI Data
 * Structure Offset field in the ROM header is used to locate the PCI data structure. The PCI data
 * structure must be located within the first 64 KB of each image's address space.
 *
 * The Code Type field in the PCI data structure is used to determine the image type. Depending on
 * the image type, the Reserved field in the ROM header may contain additional fields. See
 * OptionROMConstants.CodeType for possible Code Type values.
 *
 * The Last Image Indicator field in the PCI data structure is used to determine if the current
 * image is the last one in the expansion ROM; bit 7 indicates this, while the remaining bits are
 * reserved. If this bit is not set, the address of the next image can be calculated as such:
 *
 *   addr(next_image) = addr(current_image->rom_header) + current_image->pci_data_struct->image_len * 512
 */
public class OptionROMHeader implements StructConverter {
	// Original header fields
	private short signature;
	private int pcirOffset;

	private PCIDataStructureHeader pcirHeader;
	private DeviceList deviceList;
	private byte[] rawImage;

	/**
	 * Constructs an OptionROMHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
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

		// Read the device list (if present).
		if (pcirHeader.getDeviceListOffset() != 0) {
			reader.setPointerIndex(pcirOffset + pcirHeader.getDeviceListOffset());
			deviceList = new DeviceList(reader);
		}

		// Copy the contents of the entire image.
		reader.setPointerIndex(0);
		rawImage = reader.readNextByteArray(pcirHeader.getImageLength());
	}

	/**
	 * Returns the device list (if present).
	 *
	 * @return the device list; null if not present
	 */
	public DeviceList getDeviceList() {
		return deviceList;
	}

	/**
	 * Returns a ByteArrayInputStream for the contents of the image. Subclasses may override this
	 * to return an enclosed executable instead of the raw image.
	 *
	 * @return a ByteArrayInputStream for the contents of the image
	 */
	public ByteArrayInputStream getImageStream() {
		// For a generic option ROM with an unknown code type, just return the entire ROM as the
		// image. This will be overridden by subclasses (UEFIOptionROMHeader, etc) to only return
		// the executable.
		return new ByteArrayInputStream(rawImage);
	}

	/**
	 * Returns the PCIDataStructureHeader for the current image.
	 *
	 * @return the PCIDataStructureHeader for the current image
	 */
	public PCIDataStructureHeader getPCIRHeader() {
		return pcirHeader;
	}

	/**
	 * Returns the offset of the PCI data structure header in the current image.
	 *
	 * @return the offset of the PCI data structure header in the current image
	 */
	public int getPCIRHeaderOffset() {
		return pcirOffset;
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("option_rom_header_t", 0);
		structure.add(WORD, 2, "signature", null);
		structure.add(new ArrayDataType(BYTE, 0x16, 1), "reserved", null);
		structure.add(POINTER, 2, "pcir_offset", null);
		return structure;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("PCI Data Structure Offset: 0x%X\n", pcirOffset);
		formatter.format("%s\n", pcirHeader.toString());
		if (deviceList != null) {
			formatter.format("%s\n", deviceList.toString());
		}

		return formatter.toString();
	}
}
