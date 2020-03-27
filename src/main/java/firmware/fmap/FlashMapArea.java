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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Formatter;

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
	private long offset;
	private int size;
	private String name;
	private short flags;

	private byte[] data;

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

		long previousIndex = reader.getPointerIndex();
		reader.setPointerIndex(offset);
		data = reader.readNextByteArray(size);
		reader.setPointerIndex(previousIndex);
	}

	/**
	 * Returns an InputStream for the contents of the current flash area.
	 *
	 * @return an InputStream for the contents of the current flash area
	 */
	public InputStream getData() {
		return new ByteArrayInputStream(data);
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

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("Flash area name: %s\n", name);
		formatter.format("Flash area offset: 0x%X\n", offset);
		formatter.format("Flash area size: 0x%X\n", size);
		formatter.format("Flash area flags: %s (0x%X)",
				FlashMapConstants.FlashAreaFlags.toString(flags), flags);
		return formatter.toString();
	}
}
