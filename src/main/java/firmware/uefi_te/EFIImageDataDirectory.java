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

package firmware.uefi_te;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.IOException;

/**
 * Parser for PE32/TE image data directories, which have the following fields:
 *
 *   PE32/TE Image Data Directory
 *   +------+------+-----------------+
 *   | Type | Size | Description     |
 *   +------+------+-----------------+
 *   | u32  |    4 | Virtual Address |
 *   | u32  |    4 | Size            |
 *   +------+------+-----------------+
 *
 * Ghidra has existing classes to parse this structure, but they are dependent on PE32 NT headers.
 */
public class EFIImageDataDirectory implements StructConverter {
	private int virtualAddress;
	private int size;

	/**
	 * Constructs an EFIImageDataDirectory from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public EFIImageDataDirectory(BinaryReader reader) throws IOException {
		virtualAddress = reader.readNextInt();
		size = reader.readNextInt();
	}

	/**
	 * Returns the virtual address of the current data directory.
	 *
	 * @return the virtual address of the current data directory
	 */
	public int getVirtualAddress() {
		return virtualAddress;
	}

	/**
	 * Returns the size of the current data directory.
	 *
	 * @return the size of the current data directory
	 */
	public int getSize() {
		return size;
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("efi_image_data_dir_t", 0);
		structure.add(DWORD, 4, "virtual_address", null);
		structure.add(DWORD, 4, "size", null);
		return structure;
	}
}
