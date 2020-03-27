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
import ghidra.app.util.bin.InputStreamByteProvider;

import java.io.IOException;

/**
 * Parser for the CBFS master header, which has the following structure.
 *
 * <pre>
 *   CBFS Master Header
 *   +----------+------+--------------------------------+
 *   | Type    | Size | Description                     |
 *   +---------+------+---------------------------------+
 *   | char[4] |    4 | Signature ("ORBC")              |
 *   | u32     |    4 | Version                         |
 *   | u32     |    4 | ROM Size                        |
 *   | u32     |    4 | Boot Block Size                 |
 *   | u32     |    4 | CBFS File Alignment             |
 *   | u32     |    4 | CBFS Offset (from start of ROM) |
 *   | u32     |    4 | Architecture                    |
 *   +---------+------+---------------------------------+
 * </pre>
 *
 * There are four bytes of padding after the end of the CBFS master header.
 */
public class CBFSHeader extends CBFSFile {
	// Original header fields
	private String signature;
	private long version;
	private long romSize;
	private long bootBlockSize;
	private int alignment;
	private long offset;
	private int architecture;

	/**
	 * Constructs a CBFSHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public CBFSHeader(BinaryReader reader) throws IOException {
		super(reader);
		if (getType() != CBFSConstants.FileType.CBFS_HEADER) {
			throw new IOException("Not a valid CBFS header");
		}

		InputStreamByteProvider provider = new InputStreamByteProvider(getData(),
				getData().available());
		BinaryReader headerReader = new BinaryReader(provider, false);

		signature = headerReader.readNextAsciiString(CBFSConstants.CBFS_HEADER_SIGNATURE.length());
		if (!signature.equals(CBFSConstants.CBFS_HEADER_SIGNATURE)) {
			throw new IOException("Not a valid CBFS header");
		}

		version = headerReader.readNextUnsignedInt();
		romSize = headerReader.readNextUnsignedInt();
		bootBlockSize = headerReader.readNextUnsignedInt();
		alignment = headerReader.readNextInt();
		offset = headerReader.readNextUnsignedInt();
		architecture = headerReader.readNextInt();
	}

	/**
	 * Returns the CBFS file alignment in the current CBFS master header.
	 *
	 * @return the CBFS file alignment in the current CBFS master header
	 */
	public int getAlignment() {
		return alignment;
	}

	/**
	 * Returns the size of the boot block.
	 *
	 * @return the size of the boot block
	 */
	public long getBootBlockSize() {
		return bootBlockSize;
	}

	/**
	 * Returns the offset of the first CBFS file.
	 *
	 * @return the offset of the first CBFS file
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the size of the ROM.
	 *
	 * @return the size of the ROM
	 */
	public long getROMSize() {
		return romSize;
	}

	/**
	 * Returns the version of the current CBFS master header.
	 *
	 * @return the version of the current CBFS master header
	 */
	public long getVersion() {
		return version;
	}
}
