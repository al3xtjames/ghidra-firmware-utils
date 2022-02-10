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
 * Parser for FFS UI sections, which have the following specific field:
 *
 * <pre>
 *   UEFI FFS UI Section Header
 *   +-----------+------+----------------------------------+
 *   | Type      | Size | Description                      |
 *   +-----------+------+----------------------------------+
 *   | wchar_t[] |  var | UI Section Text (Unicode string) |
 *   +-----------+------+----------------------------------+
 * </pre>
 *
 * This header follows the common section header. See FFSSection for additional information.
 */
public class FFSUISection extends FFSSection {
	// Original header fields
	private final String uiText;

	/**
	 * Constructs a FFSUISection from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public FFSUISection(BinaryReader reader) throws IOException {
		super(reader);

		// Read the UI section text.
		uiText = reader.readNextUnicodeString((int) length() / 2);
	}

	/**
	 * Constructs a FFSUISection from a specified BinaryReader and adds it to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public FFSUISection(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih, GFile parent) throws IOException {
		this(reader);

		// Add this section to the current FS.
		fsih.storeFileWithParent(getName(), parent, -1, false, length(), this);
	}

	/**
	 * Returns the text in the current UI section.
	 *
	 * @return the text in the current UI section
	 */
	public String getText() {
		return uiText;
	}

	/**
	 * Returns FileAttributes for the current UI section.
	 *
	 * @return FileAttributes for the current UI section
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = super.getFileAttributes();
		attributes.add("Section Text", uiText);
		return attributes;
	}
}
