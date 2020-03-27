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

package firmware.cbfs;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

/**
 * Parser for CBFS file attributes, which have the following structure:
 *
 * <pre>
 *   CBFS File Attribute
 *   +------+------+------------------------------------------------+
 *   | Type | Size | Description                                    |
 *   +------+------+------------------------------------------------+
 *   | u32  |    4 | Attribute Tag                                  |
 *   | u32  |    4 | Attribute Size (including Tag and Size fields) |
 *   | u8[] |  var | Attribute Data (depends on Tag)                |
 *   +------+------+------------------------------------------------+
 * </pre>
 *
 * The Attribute Tag field is used to determine the attribute type; the contents of the Attribute
 * Data field are dependent on the attribute type. See CBFSConstants.AttributeTag for possible code
 * type values.
 *
 * This parser does not support nested file attributes, which cbfstool does support.
 */
public class CBFSFileAttribute {
	// Original header fields
	private int tag;
	private int size;
	private byte[] data;

	/**
	 * Constructs a FlashMapArea from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public CBFSFileAttribute(BinaryReader reader) throws IOException {
		tag = reader.readNextInt();
		// This is the size of the whole attribute structure, including the tag and length fields.
		size = reader.readNextInt();
		data = reader.readNextByteArray(size - 8);
	}

	public int getTag() {
		return tag;
	}

	public byte[] getData() {
		return data;
	}
}
