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

package firmware.fmap;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

/**
 * Parser for Flash Map (FMAP) layouts, as used by Chromium OS devices and coreboot.
 *
 * The flash layout is described by the flash area structures, which appear directly after the
 * flash map header. Note that the flash map header is not required to be at the start of the
 * firmware binary.
 *
 * <pre>
 *   Flash Map Header
 *   +----------+------+-------------------------+
 *   | Type     | Size | Description             |
 *   +----------+------+-------------------------+
 *   | char[8]  |    8 | Signature ("__FMAP__")  |
 *   | u8       |    1 | Major Version           |
 *   | u8       |    1 | Minor Version           |
 *   | u64      |    8 | Base Address            |
 *   | u32      |    4 | Size                    |
 *   | char[32] |   32 | Name of Firmware Binary |
 *   | u16      |    2 | Number of flash areas   |
 *   +----------+------+-------------------------+
 * </pre>
 *
 * The flash area structures immediately follow the flash map header. See FlashMapArea for a
 * description of the fields.
 */
public class FlashMapHeader {
	// Original header fields
	private String signature;
	private int majorVersion;
	private int minorVersion;
	private long baseAddress;
	private long size;
	private String name;
	private int numAreas;

	private FlashMapArea[] areas;

	/**
	 * Constructs a FlashMapHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public FlashMapHeader(BinaryReader reader) throws IOException {
		signature = reader.readNextAsciiString(FlashMapConstants.FMAP_SIGNATURE.length());
		if (!signature.equals(FlashMapConstants.FMAP_SIGNATURE)) {
			throw new IOException("Not a valid flash map");
		}

		// Read the header fields.
		majorVersion = reader.readNextUnsignedByte();
		minorVersion = reader.readNextUnsignedByte();
		baseAddress = reader.readNextLong();
		size = reader.readNextUnsignedInt();
		name = reader.readNextAsciiString(FlashMapConstants.FMAP_NAME_LEN).trim();

		// Read each flash area.
		numAreas = reader.readNextUnsignedShort();
		areas = new FlashMapArea[numAreas];
		for (int i = 0; i < numAreas; i++) {
			areas[i] = new FlashMapArea(reader);
		}
	}

	/**
	 * Returns an array of FlashMapAreas.
	 *
	 * @return an array of FlashMapAreas
	 */
	public FlashMapArea[] getAreas() {
		return areas;
	}

	/**
	 * Returns the base address for the current firmware binary.
	 *
	 * @return the base address for the current firmware binary
	 */
	public long getBaseAddress() {
		return baseAddress;
	}

	/**
	 * Returns the name of the current firmware binary.
	 *
	 * @return the name of the current firmware binary
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the version string for the current firmware binary.
	 *
	 * @return the version string for the current firmware binary
	 */
	public String getVersion() {
		return String.format("%d.%d", majorVersion, minorVersion);
	}
}
