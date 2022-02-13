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
import java.util.Formatter;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * UEFIFile implementation for the contents of a raw FFS file.
 */
public class FFSRawFile implements UEFIFile {
	private final long base;
	private final int length;
	private final ByteProvider provider;

	/**
	 * Constructs a FFSRawFile from a specified BinaryReader and adds it to a
	 * specified FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public FFSRawFile(BinaryReader reader, int length, FileSystemIndexHelper<UEFIFile> fsih, GFile parent)
			throws IOException {
		base = reader.getPointerIndex();
		this.length = length;
		provider = new ByteProviderWrapper(reader.getByteProvider(), base, length);
		reader.setPointerIndex(reader.getPointerIndex() + length);

		// Add this file to the FS.
		fsih.storeFileWithParent(UEFIFirmwareVolumeFileSystem.getFSFormattedName(this, parent, fsih), parent, -1,
				false, length(), this);
	}

	/**
	 * Returns a ByteProvider for the contents of the current raw FFS file.
	 *
	 * @return a ByteProvider for the contents of the current raw FFS file
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

	/**
	 * Returns the name of the current raw FFS file.
	 *
	 * @return the name of the current raw FFS file
	 */
	@Override
	public String getName() {
		return "Raw file";
	}

	/**
	 * Returns the length of the current raw FFS file.
	 *
	 * @return the length of the current raw FFS file
	 */
	@Override
	public long length() {
		return length;
	}

	/**
	 * Returns FileAttributes for the current GUID-defined section.
	 *
	 * @return FileAttributes for the current GUID-defined section
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add(FileAttributeType.SIZE_ATTR, Long.valueOf(length));
		attributes.add("Base", String.format("%#x", base));
		return attributes;
	}
}
