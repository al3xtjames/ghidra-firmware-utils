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
import ghidra.app.util.bin.ByteArrayProvider;

import java.io.IOException;

/**
 * Parser for CBFS file compression attributes, which are CBFS file attributes with the compression
 * tag. The structure is as follows:
 *
 * <pre>
 *   CBFS File Compression Attribute
 *   +------+------+------------------------------------------------+
 *   | Type | Size | Description                                    |
 *   +------+------+------------------------------------------------+
 *   | u32  |    4 | Attribute Tag (0x42435A4C, big endian)         |
 *   | u32  |    4 | Attribute Size (including Tag and Size fields) |
 *   | u32  |    4 | Compression Type                               |
 *   | u32  |    4 | Uncompressed Size                              |
 *   +------+------+------------------------------------------------+
 * </pre>
 *
 * See CBFSConstants.CompressionAlgorithm for possible Compression Type values.
 */
public class CBFSCompressionAttribute extends CBFSFileAttribute {
	// Original header fields
	private final int compressionType;
	private final long uncompressedSize;

	/**
	 * Constructs a CBFSCompressionAttribute from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public CBFSCompressionAttribute(BinaryReader reader) throws IOException {
		super(reader);
		if (getTag() != CBFSConstants.AttributeTag.COMPRESSION) {
			throw new IOException("Attribute tag mismatch: expected compression (0x42435A4C)");
		}

		ByteArrayProvider provider = new ByteArrayProvider(super.getData());
		BinaryReader dataReader = new BinaryReader(provider, false);
		compressionType = dataReader.readNextInt();
		uncompressedSize = dataReader.readNextUnsignedInt();
	}

	/**
	 * Returns the compression algorithm used by the CBFS file.
	 *
	 * @return the compression algorithm used by the CBFS file
	 */
	public int getCompressionType() {
		return compressionType;
	}

	/**
	 * Returns the uncompressed size of the CBFS file.
	 *
	 * @return the uncompressed size of the CBFS file
	 */
	public long getUncompressedLength() {
		return uncompressedSize;
	}
}
