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
import java.io.InputStream;

import ghidra.app.util.bin.BinaryReader;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;

/**
 * Parser for FFS firmware volume image sections. These do not have additional header fields; see
 * FFSSection for additional information regarding the common FFS section header.
 *
 * Firmware volume image sections contain an embedded UEFI firmware volume.
 */
public class FFSVolumeImageSection extends FFSSection {
	/**
	 * Constructs a FFSVolumeImageSection from a specified BinaryReader and adds it to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public FFSVolumeImageSection(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih, GFile parent)
			throws IOException {
		super(reader);

		// Add this section to the current FS.
		GFile fileImpl = fsih.storeFileWithParent(getName(), parent, -1, true, -1, this);

		// Add the nested firmware volume to the FS.
		new UEFIFirmwareVolumeHeader(reader, fsih, fileImpl, true);
	}

	/**
	 * Returns an InputStream for the contents of the current firmware volume image section. This
	 * will return null, as it shouldn't be possible to call this; firmware volume image sections
	 * are added to the FS as directories.
	 *
	 * @return an InputStream for the contents of the current firmware volume image section
	 */
	@Override
	public InputStream getData() {
		return null;
	}
}
