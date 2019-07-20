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

package firmware.uefi_fv;

import firmware.common.UUIDUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.formats.gfilesystem.GFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

/**
 * Parser for FFS freeform sections, which have the following specific field:
 *
 *   UEFI FFS UI Section Header
 *   +------------+------+--------------+
 *   | Type       | Size | Description  |
 *   +------------+------+--------------+
 *   | efi_guid_t |   16 | Subtype GUID |
 *   +------------+------+--------------+
 *
 * This header follows the common section header. See FFSSection for additional information.
 */
public class FFSFreeformSubtypeSection extends FFSSection {
	// Original header fields
	private UUID subTypeGuid;
	private byte[] data;

	/**
	 * Constructs a FFSFreeformSubtypeSection from a specified BinaryReader and adds it to a
	 * specified UEFIFirmwareVolumeFileSystem.
	 *
	 * @param reader the specified BinaryReader
	 * @param fs     the specified UEFIFirmwareVolumeFileSystem
	 * @param parent the parent directory in the specified UEFIFirmwareVolumeFileSystem
	 */
	public FFSFreeformSubtypeSection(BinaryReader reader, UEFIFirmwareVolumeFileSystem fs,
			GFile parent) throws IOException {
		super(reader);

		subTypeGuid = UUIDUtils.fromBinaryReader(reader);
		data = reader.readNextByteArray((int) length());

		// Add this section to the current FS.
		fs.addFile(parent, this, getName(), false);
	}

	/**
	 * Returns an InputStream for the contents of the current freeform section.
	 *
	 * @return an InputStream for the contents of the current freeform section
	 */
	@Override
	public InputStream getData() {
		return new ByteArrayInputStream(data);
	}

	/**
	 * Returns the length of the freeform section header.
	 *
	 * @return the length of the freeform section header
	 */
	@Override
	public int getHeaderLength() {
		return super.getHeaderLength() + 16;
	}

	/**
	 * Returns the name of the current freeform section.
	 *
	 * @return the name of the current freeform section
	 */
	@Override
	public String getName() {
		return super.getName() + " - " + UUIDUtils.getName(subTypeGuid);
	}

	/**
	 * Returns the length of the body in the current freeform section.
	 *
	 * @return the length of the body in the current freeform section
	 */
	@Override
	public long length() {
		return super.length() - 16;
	}

	/**
	 * Returns a string representation of the current freeform section.
	 *
	 * @return a string representation of the current freeform section
	 */
	@Override
	public String toString() {
		return super.toString() +
				"\nSubtype GUID: " + subTypeGuid.toString();
	}
}
