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
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * Parser for Intel flash regions (using region information defined in a flash descriptor).
 */
public class IntelFlashRegion {
	private final int baseAddress;
	private final int length;
	private final int type;
	private final ByteProvider provider;

	/**
	 * Constructs an IntelFlashRegion from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 * @param length the length of the flash region in bytes
	 * @param type   the region type (see IntelFlashDescriptorConstants.FlashRegionType)
	 */
	public IntelFlashRegion(BinaryReader reader, int length, int type) {
		baseAddress = (int) reader.getPointerIndex();
		this.length = length;
		this.type = type;
		provider = new ByteProviderWrapper(reader.getByteProvider(), baseAddress, length);
	}

	/**
	 * Returns a ByteProvider for the contents of the current flash region.
	 *
	 * @return a ByteProvider for the contents of the current flash region
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

	/**
	 * Returns the current flash region's type.
	 *
	 * @return the current flash region's type
	 */
	public int getType() {
		return type;
	}

	/**
	 * Returns the length of the current flash region.
	 *
	 * @return the length of the current flash region
	 */
	public int length() {
		return length;
	}

	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add(FileAttributeType.NAME_ATTR, IntelFlashDescriptorConstants.FlashRegionType.toString(type));
		attributes.add(FileAttributeType.SIZE_ATTR, Long.valueOf(length));
		attributes.add("Base Address", String.format("%#x", baseAddress));
		return attributes;
	}
}
