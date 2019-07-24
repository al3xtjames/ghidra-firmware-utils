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

import ghidra.app.util.bin.BinaryReader;
import ghidra.formats.gfilesystem.GFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for generic FFS sections. This only parses the common FFS section header; the rest of the
 * section is treated as the body.
 */
public class FFSGenericSection extends FFSSection {
	private byte[] data;

	/**
	 * Constructs a FFSGenericSection from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public FFSGenericSection(BinaryReader reader) throws IOException {
		super(reader);
		data = reader.readNextByteArray((int) length());
	}

	/**
	 * Constructs a FFSGenericSection from a specified BinaryReader and adds it to a specified
	 * UEFIFirmwareVolumeFileSystem.
	 *
	 * @param reader the specified BinaryReader
	 * @param fs     the specified UEFIFirmwareVolumeFileSystem
	 * @param parent the parent directory in the specified UEFIFirmwareVolumeFileSystem
	 */
	public FFSGenericSection(BinaryReader reader, UEFIFirmwareVolumeFileSystem fs,
			GFile parent) throws IOException {
		this(reader);

		// Add this section to the current FS.
		fs.addFile(parent, this, getName(), false);
	}

	/**
	 * Returns an InputStream for the contents of the current FFS section.
	 *
	 * @return an InputStream for the contents of the current FFS section
	 */
	@Override
	public InputStream getData() {
		return new ByteArrayInputStream(data);
	}
}
