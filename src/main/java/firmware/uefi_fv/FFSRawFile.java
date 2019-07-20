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
import java.util.Formatter;

/**
 * UEFIFile implementation for the contents of a raw FFS file.
 */
public class FFSRawFile implements UEFIFile {
	private long base;
	private byte[] data;

	/**
	 * Constructs a FFSRawFile from a specified BinaryReader and adds it to a
	 * specified UEFIFirmwareVolumeFileSystem.
	 *
	 * @param reader the specified BinaryReader
	 * @param fs     the specified UEFIFirmwareVolumeFileSystem
	 * @param parent the parent directory in the specified UEFIFirmwareVolumeFileSystem
	 */
	public FFSRawFile(BinaryReader reader, int length, UEFIFirmwareVolumeFileSystem fs,
			GFile parent) throws IOException {
		base = reader.getPointerIndex();
		data = reader.readNextByteArray(length);

		// Add this file to the FS.
		fs.addFile(parent, this, false);
	}

	/**
	 * Returns an InputStream for the contents of the current raw FFS file.
	 *
	 * @return an InputStream for the contents of the current raw FFS file
	 */
	public InputStream getData() {
		return new ByteArrayInputStream(data);
	}

	/**
	 * Returns the name of the current raw FFS file.
	 *
	 * @return the name of the current raw FFS file
	 */
	public String getName() {
		return "Raw file";
	}

	/**
	 * Returns the length of the current raw FFS file.
	 *
	 * @return the length of the current raw FFS file
	 */
	public long length() {
		return data.length;
	}

	/**
	 * Returns a string representation of the current raw FFS file.
	 *
	 * @return a string representation of the current raw FFS file
	 */
	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("Base: 0x%X\n", base);
		formatter.format("Size: 0x%X", data.length);
		return formatter.toString();
	}
}
