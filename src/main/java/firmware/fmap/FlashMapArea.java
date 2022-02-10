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
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

import java.io.IOException;

/**
 * Parser for flash areas, which have the following structure:
 *
 * <pre>
 *   Flash Map Header
 *   +----------+------+-------------------------------------------------------+
 *   | Type     | Size | Description                                           |
 *   +----------+------+-------------------------------------------------------+
 *   | u32      |    4 | Offset (Relative to Base Address in Flash Map Header) |
 *   | u32      |    4 | Size of Flash Area                                    |
 *   | char[32] |   32 | Name of Flash Area                                    |
 *   | u16      |    2 | Flash Area Flags                                      |
 *   +----------+------+-------------------------------------------------------+
 * </pre>
 *
 * See FlashMapConstants.AreaFlags for possible Flash Area Flags.
 */
public class FlashMapArea {
	// Original header fields
	private final long offset;
	private final int size;
	private final String name;
	private final short flags;

	private final ByteProvider provider;

	/**
	 * Constructs a FlashMapArea from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public FlashMapArea(BinaryReader reader) throws IOException {
		offset = reader.readNextUnsignedInt();
		size = reader.readNextInt();
		name = reader.readNextAsciiString(FlashMapConstants.FMAP_NAME_LEN).trim();
		flags = reader.readNextShort();

		provider = new ByteProviderWrapper(reader.getByteProvider(), offset, size);
	}

	/**
	 * Returns a ByteProvider for the contents of the current flash area.
	 *
	 * @return a ByteProvider for the contents of the current flash area
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

	/**
	 * Returns the name of the current flash area.
	 *
	 * @return the name of the current flash area
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the offset of the current flash area (relative to the base).
	 *
	 * @return the offset of the current flash area
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the length of the current flash area.
	 *
	 * @return the length of the current flash area
	 */
	public int length() {
		return size;
	}

	/**
	 * Returns FileAttributes for the current flash area.
	 *
	 * @return FileAttributes for the current flash area
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add(FileAttributeType.NAME_ATTR, name);
		attributes.add(FileAttributeType.SIZE_ATTR, Long.valueOf(size));
		attributes.add("Offset", offset);
		attributes.add("Flags", FlashMapConstants.FlashAreaFlags.toString(flags));
		return attributes;
	}
}
