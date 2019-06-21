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

package firmware.ifd;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteOrder;
import java.util.ArrayList;

import org.apache.commons.compress.utils.BitInputStream;

/**
 * Parser for Intel Flash/Firmware Descriptors.
 *
 * The IFD header (placed at the start of the IFD) contains the following fields:
 *
 *   Intel Flash Descriptor Header
 *   +--------+------+---------------------------------------+
 *   | Type   | Size | Description                           |
 *   +--------+------+---------------------------------------+
 *   | u8[16] |   16 | Reset Vector (0xFF bytes)             |
 *   | u32    |    4 | Signature (0x0FF0A55A, little endian) |
 *   +--------+------+---------------------------------------+
 *
 * This is immediately followed by the flash descriptor map. This parser only handles FLMAP0, which
 * has the following bit fields:
 *
 *   FLMAP0
 *   +------+--------------------------------+
 *   | Bits | Description                    |
 *   +------+--------------------------------+
 *   |    8 | Component Section Base Address |
 *   |    2 | Number of Flash Chips          |
 *   |    6 | Reserved                       |
 *   |    8 | Region Section Base Address    |
 *   |    3 | Number of Regions              |
 *   |    5 | Reserved                       |
 *   +------+--------------------------------+
 *
 * The component/region section base addresses are truncated; multiply them by 0x10 to get the
 * actual section base address.
 *
 * The component section begins with the following bit fields (describing the flash parameters):
 *
 *   Intel Flash Parameters
 *   +------+---------------------------------+
 *   | Bits | Description                     |
 *   +------+---------------------------------+
 *   |    4 | First Flash Chip Density        |
 *   |    4 | Second Flash Chip Density       |
 *   |    9 | Reserved                        |
 *   |    3 | Read Frequency                  |
 *   |    1 | Fast Read Enabled               |
 *   |    3 | Fast Read Frequency             |
 *   |    3 | Write Frequency                 |
 *   |    3 | Flash Read Status Frequency     |
 *   |    1 | Dual Output Fast Read Supported |
 *   +------+---------------------------------+
 *
 * See IntelFlashDescriptorConstants.FlashFrequency for some possible Read Frequency values. This
 * field can be used to determine the IFD version - IFD v1 always has a read frequency of 20 MHz.
 *
 * The region section contains the base address and length for each flash region:
 *
 *   Region Component Section
 *   +------+------+------------------------------------------------------------+
 *   | Type | Size | Description                                                |
 *   +------+------+------------------------------------------------------------+
 *   | u16  |    2 | Flash Descriptor Region Base Address                       |
 *   | u16  |    2 | Flash Descriptor Region Limit Address                      |
 *   | u16  |    2 | BIOS Region Base Address                                   |
 *   | u16  |    2 | BIOS Region Limit Address                                  |
 *   | u16  |    2 | Intel Management Engine Region Base Address                |
 *   | u16  |    2 | Intel Management Engine Region Limit Address               |
 *   | u16  |    2 | Gigabit Ethernet Region Base Address                       |
 *   | u16  |    2 | Gigabit Ethernet Region Limit Address                      |
 *   | u16  |    2 | Platform Data Region Base Address                          |
 *   | u16  |    2 | Platform Data Region Limit Address                         |
 *   | u16  |    2 | Device Expansion Region 1 Base Address (IFD v2 only)       |
 *   | u16  |    2 | Device Expansion Region 1 Limit Address (IFD v2 only)      |
 *   | u16  |    2 | Secondary BIOS Region Base Address (IFD v2 only)           |
 *   | u16  |    2 | Secondary BIOS Region Limit Address (IFD v2 only)          |
 *   | u16  |    2 | CPU Microcode Base Address (IFD v2 only)                   |
 *   | u16  |    2 | CPU Microcode Region Limit Address (IFD v2 only)           |
 *   | u16  |    2 | Embedded Controller Region Base Address (IFD v2 only)      |
 *   | u16  |    2 | Embedded Controller Region Limit Address (IFD v2 only)     |
 *   | u16  |    2 | Device Expansion Region 2 Base Address (IFD v2 only)       |
 *   | u16  |    2 | Device Expansion Region 2 Limit Address (IFD v2 only)      |
 *   | u16  |    2 | Intel Innovation Engine Region Base Address (IFD v2 only)  |
 *   | u16  |    2 | Intel Innovation Engine Region Limit Address (IFD v2 only) |
 *   | u16  |    2 | 10 Gigabit Ethernet Region 1 Base Address (IFD v2 only)    |
 *   | u16  |    2 | 10 Gigabit Ethernet Region 1 Limit Address (IFD v2 only)   |
 *   | u16  |    2 | 10 Gigabit Ethernet Region 2 Base Address (IFD v2 only)    |
 *   | u16  |    2 | 10 Gigabit Ethernet Region 2 Limit Address (IFD v2 only)   |
 *   | u16  |    2 | Region 13 Base Address (reserved, IFD v2 only)             |
 *   | u16  |    2 | Region 13 Limit Address (reserved, IFD v2 only)            |
 *   | u16  |    2 | Region 14 Base Address (reserved, IFD v2 only)             |
 *   | u16  |    2 | Region 14 Limit Address (reserved, IFD v2 only)            |
 *   | u16  |    2 | Platform Trust Technology Base Address (IFD v2 only)       |
 *   | u16  |    2 | Platform Trust Technology Limit Address (IFD v2 only)      |
 *   +------+------+------------------------------------------------------------+
 *
 * Each region's base address is truncated; multiply the value by 0x1000 to get the actual base
 * address. The same applies for the limit address.
 *
 * For additional information, see UEFITool's descriptor.h:
 * https://github.com/LongSoft/UEFITool/blob/ec3809159997bb7cc39a746a9d17f8385866d2a2/common/descriptor.h
 */
public class IntelFlashDescriptor {
	// Original header fields
	private int signature;

	// FLMAP0 fields
	private short componentBase;
	private byte numFlashChips;
	private short regionBase;
	private byte numRegions;

	private long headerOffset;
	private int ifdVersion;
	private ArrayList<IntelFlashRegion> regions;

	/**
	 * Constructs an IntelFlashDescriptor from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public IntelFlashDescriptor(BinaryReader reader) throws IOException {
		// Skip the IFD vector (16 0xFF bytes).
		headerOffset = reader.getPointerIndex();
		reader.setPointerIndex(reader.getPointerIndex() + 16);

		signature = reader.readNextInt();
		if (signature != IntelFlashDescriptorConstants.IFD_SIGNATURE) {
			throw new IOException("Not a valid Intel flash descriptor");
		}

		// Read the fields in FLMAP0.
		InputStream inputStream = reader.getByteProvider().getInputStream(reader.getPointerIndex());
		BitInputStream bitInputStream = new BitInputStream(inputStream, ByteOrder.LITTLE_ENDIAN);
		componentBase = (short) bitInputStream.readBits(8);
		numFlashChips = (byte) bitInputStream.readBits(2);
		bitInputStream.readBits(6);
		regionBase = (short) bitInputStream.readBits(8);
		numRegions = (byte) bitInputStream.readBits(3);
		bitInputStream.readBits(5);

		Msg.debug(this, String.format("Component section base address = 0x%X", componentBase));
		Msg.debug(this, "Number of flash chips = " + numFlashChips);
		Msg.debug(this, String.format("Region section base address = 0x%X", regionBase));
		Msg.debug(this, "Number of regions = " + numRegions);

		// Read the read clock frequency in the component section to determine the IFD version.
		inputStream = reader.getByteProvider().getInputStream(headerOffset + componentBase * 0x10);
		bitInputStream = new BitInputStream(inputStream, ByteOrder.LITTLE_ENDIAN);
		bitInputStream.readBits(4 + 4 + 9);
		byte readClockFrequency = (byte) bitInputStream.readBits(3);

		// IFD v1 has a hardcoded flash read frequency of 20 MHz.
		if (readClockFrequency == IntelFlashDescriptorConstants.FlashFrequency.FREQ_20_MHZ) {
			ifdVersion = 1;
		} else {
			ifdVersion = 2;
		}

		Msg.debug(this, "IFD version = " + ifdVersion);

		// Read the region section.
		reader.setPointerIndex(headerOffset + regionBase * 0x10);
		int descriptorBase = reader.readNextUnsignedShort();
		int descriptorLimit = reader.readNextUnsignedShort();
		int biosBase = reader.readNextUnsignedShort();
		int biosLimit = reader.readNextUnsignedShort();
		int meBase = reader.readNextUnsignedShort();
		int meLimit = reader.readNextUnsignedShort();
		int gbeBase = reader.readNextUnsignedShort();
		int gbeLimit = reader.readNextUnsignedShort();
		int pdrBase = reader.readNextUnsignedShort();
		int pdrLimit = reader.readNextUnsignedShort();
		int devExp1Base = reader.readNextUnsignedShort();
		int devExp1Limit = reader.readNextUnsignedShort();
		int secondaryBIOSBase = reader.readNextUnsignedShort();
		int secondaryBIOSLimit = reader.readNextUnsignedShort();
		int microcodeBase = reader.readNextUnsignedShort();
		int microcodeLimit = reader.readNextUnsignedShort();
		int ecBase = reader.readNextUnsignedShort();
		int ecLimit = reader.readNextUnsignedShort();
		int devExp2Base = reader.readNextUnsignedShort();
		int devExp2Limit = reader.readNextUnsignedShort();
		int ieBase = reader.readNextUnsignedShort();
		int ieLimit = reader.readNextUnsignedShort();
		int tenGbe1Base = reader.readNextUnsignedShort();
		int tenGbe1Limit = reader.readNextUnsignedShort();
		int tenGbe2Base = reader.readNextUnsignedShort();
		int tenGbe2Limit = reader.readNextUnsignedShort();
		int region13Base = reader.readNextUnsignedShort();
		int region13Limit = reader.readNextUnsignedShort();
		int region14Base = reader.readNextUnsignedShort();
		int region14Limit = reader.readNextUnsignedShort();
		int pttBase = reader.readNextUnsignedShort();
		int pttLimit = reader.readNextUnsignedShort();

		// Add each flash region.
		regions = new ArrayList<>();
		reader.setPointerIndex(headerOffset);
		regions.add(new IntelFlashRegion(reader, IntelFlashDescriptorConstants.DESCRIPTOR_SIZE,
				IntelFlashDescriptorConstants.FlashRegionType.FLASH_DESCRIPTOR));
		if ((biosLimit + 1 - biosBase) * 0x1000 == reader.length() - headerOffset) {
			// For some older Gigabyte systems, the BIOS region in the flash descriptor spans the
			// whole chip. Manually calculate the BIOS region base address using the ME region's
			// limit address (which should be correct).
			if (meLimit != 0) {
				biosBase = meLimit + 1;
			}
		}

		addRegion(reader, biosBase, biosLimit, IntelFlashDescriptorConstants.FlashRegionType.BIOS);
		addRegion(reader, meBase, meLimit,
				IntelFlashDescriptorConstants.FlashRegionType.MANAGEMENT_ENGINE);
		addRegion(reader, gbeBase, gbeLimit,
				IntelFlashDescriptorConstants.FlashRegionType.GIGABIT_ETHERNET);
		addRegion(reader, pdrBase, pdrLimit,
				IntelFlashDescriptorConstants.FlashRegionType.PLATFORM_DATA);

		if (ifdVersion == 2) {
			addRegion(reader, devExp1Base, devExp1Limit,
					IntelFlashDescriptorConstants.FlashRegionType.DEVICE_EXPANSION_1);
			addRegion(reader, secondaryBIOSBase, secondaryBIOSLimit,
					IntelFlashDescriptorConstants.FlashRegionType.SECONDARY_BIOS);
			addRegion(reader, microcodeBase, microcodeLimit,
					IntelFlashDescriptorConstants.FlashRegionType.MICROCODE);
			addRegion(reader, ecBase, ecLimit,
					IntelFlashDescriptorConstants.FlashRegionType.EMBEDDED_CONTROLLER);
			addRegion(reader, devExp2Base, devExp2Limit,
					IntelFlashDescriptorConstants.FlashRegionType.DEVICE_EXPANSION_2);
			addRegion(reader, ieBase, ieLimit,
					IntelFlashDescriptorConstants.FlashRegionType.INNOVATION_ENGINE);
			addRegion(reader, tenGbe1Base, tenGbe1Limit,
					IntelFlashDescriptorConstants.FlashRegionType.TEN_GIGABIT_ETHERNET_1);
			addRegion(reader, tenGbe2Base, tenGbe2Limit,
					IntelFlashDescriptorConstants.FlashRegionType.TEN_GIGABIT_ETHERNET_2);
			addRegion(reader, pttBase, pttLimit,
					IntelFlashDescriptorConstants.FlashRegionType.PLATFORM_TRUST_TECHNOLOGY);
		}
	}

	/**
	 * Returns the flash regions defined in the current flash descriptor.
	 *
	 * @return the flash regions defined in the current flash descriptor
	 */
	public ArrayList<IntelFlashRegion> getRegions() {
		return regions;
	}

	/**
	 * Adds a flash region to the list of flash regions using a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 * @param base   the region's base address (truncated)
	 * @param limit  the region's limit address (truncated)
	 * @param type   the region's type
	 */
	private void addRegion(BinaryReader reader, int base, int limit, int type) throws IOException {
		int size = limit > 0 ? (limit + 1 - base) * 0x1000 : 0;
		if (size == 0) {
			return;
		}

		reader.setPointerIndex(headerOffset + base * 0x1000);
		regions.add(new IntelFlashRegion(reader, size, type));
		Msg.debug(this, String.format("Adding %s region (base = 0x%X, size = 0x%X",
				IntelFlashDescriptorConstants.FlashRegionType.toString(type), base * 0x1000,
				size));
	}
}
