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

import java.io.IOException;
import java.util.UUID;

import firmware.common.UUIDUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * Parser for FFS freeform sections, which have the following specific field:
 *
 * <pre>
 *   UEFI FFS UI Section Header
 *   +------------+------+--------------+
 *   | Type       | Size | Description  |
 *   +------------+------+--------------+
 *   | efi_guid_t |   16 | Subtype GUID |
 *   +------------+------+--------------+
 * </pre>
 *
 * This header follows the common section header. See FFSSection for additional information.
 */
public class FFSFreeformSubtypeSection extends FFSSection {
	// Original header fields
	private final UUID subTypeGuid;

	private final ByteProvider provider;

	/**
	 * Constructs a FFSFreeformSubtypeSection from a specified BinaryReader and adds it to a
	 * specified FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public FFSFreeformSubtypeSection(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih, GFile parent)
			throws IOException {
		super(reader);

		subTypeGuid = UUIDUtils.fromBinaryReader(reader);
		provider = new ByteProviderWrapper(reader.getByteProvider(), reader.getPointerIndex(), length());
		reader.setPointerIndex(reader.getPointerIndex() + length());

		// Add this section to the current FS.
		fsih.storeFileWithParent(getName(), parent, -1, false, length(), this);
	}

	/**
	 * Returns a ByteProvider for the contents of the current freeform section.
	 *
	 * @return a ByteProvider for the contents of the current freeform section
	 */
	@Override
	public ByteProvider getByteProvider() {
		return provider;
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
	 * Returns FileAttributes for the current freeform section.
	 *
	 * @return FileAttributes for the current freeform section
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = super.getFileAttributes();
		attributes.add("Subtype GUID", subTypeGuid.toString());
		return attributes;
	}
}
