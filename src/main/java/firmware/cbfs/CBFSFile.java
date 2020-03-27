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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Formatter;

import org.apache.commons.compress.compressors.lz4.FramedLZ4CompressorInputStream;
import org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream;

import ghidra.app.util.bin.BinaryReader;

/**
 * Parser for CBFS files, which have the following structure:
 *
 *   CBFS File Header
 *   +---------+--------------------------------+
 *   | Type    | Size | Description             |
 *   +---------+--------------------------------+
 *   | char[8] |    8 | Signature ("LARCHIVE")  |
 *   | u32     |    4 | File Size               |
 *   | u32     |    4 | File Type               |
 *   | u32     |    4 | File Attributes Offset  |
 *   | u32     |    4 | Offset of File Contents |
 *   | char[]  |  var | File Name (C string)    |
 *   +---------+--------------------------------+
 *
 * If nonzero, the File Attributes Offset field points to a CBFS file attribute structure. See
 * CBFSFileAttribute for details on this structure.
 *
 * The File Name field is a null-terminated C string.
 */
public class CBFSFile {
	// Original header fields
	private byte[] signature;
	private int size;
	private int type;
	private long attributesOffset;
	private long offset;
	private String name;

	private CBFSFileAttribute attribute;
	private byte[] data;

	/**
	 * Constructs a CBFSFile from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public CBFSFile(BinaryReader reader) throws IOException {
		long startIndex = reader.getPointerIndex();

		signature = reader.readNextByteArray(CBFSConstants.CBFS_FILE_SIGNATURE.length);
		if (!Arrays.equals(CBFSConstants.CBFS_FILE_SIGNATURE, signature)) {
			throw new IOException("Not a valid CBFS file");
		}

		size = reader.readNextInt();
		type = reader.readNextInt();
		attributesOffset = reader.readNextUnsignedInt();
		offset = reader.readNextUnsignedInt();
		name = reader.readNextNullTerminatedAsciiString();

		// The attributes offset should point past the end of the CBFS file structure.
		if (attributesOffset != 0 && attributesOffset > CBFSConstants.CBFS_FILE_SIZE) {
			// TODO: Handle nested file attributes: additional file attributes may be stored in the
			// first attribute's data section
			reader.setPointerIndex(startIndex + attributesOffset);
			attribute = CBFSFileAttributeFactory.parseCBFSFileAttribute(reader);
		}

		reader.setPointerIndex(startIndex + offset);
		data = reader.readNextByteArray(size);
	}

	/**
	 * Returns an InputStream for the contents of the current file. Compressed files will be
	 * wrapped in a CompressorInputStream for transparent extraction.
	 *
	 * @return an InputStream for the contents of the current file
	 */
	public InputStream getData() throws IOException {
		ByteArrayInputStream dataInputStream = new ByteArrayInputStream(data);

		// Extract the file if compression is used (specified in a compression attribute).
		if (attribute != null && attribute instanceof CBFSCompressionAttribute) {
			switch (((CBFSCompressionAttribute) attribute).getCompressionType()) {
				case CBFSConstants.CompressionAlgorithm.LZMA:
					return new LZMACompressorInputStream(dataInputStream);
				case CBFSConstants.CompressionAlgorithm.LZ4:
					return new FramedLZ4CompressorInputStream(dataInputStream);
			}
		}

		return dataInputStream;
	}

	/**
	 * Returns the name of the current file.
	 *
	 * @return the name of the current file
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the offset of the current file's contents.
	 *
	 * @return the offset of the current file's contents.
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the current file's type.
	 *
	 * @return the current file's type
	 */
	public int getType() {
		return type;
	}

	/**
	 * Returns the size of the current file.
	 *
	 * @return the size of the current file
	 */
	public int length() {
		return size;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("CBFS file name: %s\n", name);
		formatter.format("CBFS file size: 0x%X\n", size);
		formatter.format("CBFS file type: %s (0x%X)\n", CBFSConstants.FileType.toString(type),
				type);
		if (attribute != null && attribute instanceof CBFSCompressionAttribute) {
			switch (((CBFSCompressionAttribute) attribute).getCompressionType()) {
				case CBFSConstants.CompressionAlgorithm.LZMA:
					formatter.format("CBFS file attribute: Compressed (LZMA)");
					break;
				case CBFSConstants.CompressionAlgorithm.LZ4:
					formatter.format("CBFS file attribute: Compressed (LZ4)");
					break;
			}
		}

		return formatter.toString();
	}
}
