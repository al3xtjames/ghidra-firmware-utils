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

import ghidra.app.util.bin.BinaryReader;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * Parser for FFS version sections, which have the following specific fields:
 *
 * <pre>
 *   UEFI FFS UI Section Header
 *   +-----------+------+---------------------------------+
 *   | Type      | Size | Description                     |
 *   +-----------+------+---------------------------------+
 *   | u16       |    2 | Build Number                    |
 *   | wchar_t[] |  var | Version String (Unicode string) |
 *   +-----------+------+---------------------------------+
 * </pre>
 *
 * This header follows the common section header. See FFSSection for additional information.
 */
public class FFSVersionSection extends FFSSection {
	// Original header fields
	private final short buildNumber;
	private final String versionString;

	/**
	 * Constructs a FFSVersionSection from a specified BinaryReader and adds it to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 * @throws IOException
	 */
	public FFSVersionSection(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih,
			GFile parent) throws IOException {
		super(reader);

		buildNumber = reader.readNextShort();
		versionString = reader.readNextUnicodeString((int) length() / 2);

		// Add this section to the current FS.
		fsih.storeFileWithParent(getName(), parent, -1, false, length(), this);
	}

	/**
	 * Returns the build number for the current version section.
	 *
	 * @return the build number for the current version section
	 */
	public short getBuildNumber() {
		return buildNumber;
	}

	/**
	 * Returns the length of the version section header.
	 *
	 * @return the length of the version section header
	 */
	@Override
	public int getHeaderLength() {
		return UEFIFFSConstants.FFS_SECTION_HEADER_SIZE + 2;
	}

	/**
	 * Returns the version string for the current version section.
	 *
	 * @return the version string for the current version section
	 */
	public String getVersionString() {
		return versionString;
	}

	/**
	 * Returns the length of the body in the current version section.
	 *
	 * @return the length of the body in the current version section
	 */
	@Override
	public long length() {
		return super.length() - 2;
	}

	/**
	 * Returns FileAttributes for the current version section.
	 *
	 * @return FileAttributes for the current version section
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = super.getFileAttributes();
		attributes.add("Version String", versionString);
		return attributes;
	}
}
