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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.IOException;

/**
 * Parser for PE32/TE section headers, which have the following fields:
 *
 *   PE32/TE Image Section Header
 *   +---------+------+------------------------+
 *   | Type    | Size | Description            |
 *   +---------+------+------------------------+
 *   | char[8] |    8 | Name                   |
 *   | u32     |    4 | Virtual Size           |
 *   | u32     |    4 | Virtual Address        |
 *   | u32     |    4 | Raw Data Size          |
 *   | u32     |    4 | Raw Data Pointer       |
 *   | u32     |    4 | Relocations Pointer    |
 *   | u32     |    4 | Line Numbers Pointer   |
 *   | u16     |    2 | Number of Relocations  |
 *   | u16     |    2 | Number of Line Numbers |
 *   | u32     |    4 | Characteristics        |
 *   +---------+------+------------------------+
 *
 * Ghidra has existing classes to parse this structure, but they are dependent on PE32 NT headers.
 */
public class EFIImageSectionHeader implements StructConverter {
	// Original header fields
	private String name;
	private int virtualSize;
	private int virtualAddress;
	private int rawDataSize;
	private int rawDataPointer;
	private int relocationsPointer;
	private int lineNumbersPointer;
	private short numRelocations;
	private short numLineNumbers;
	private int characteristics;

	/**
	 * Constructs an EFIImageSectionHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public EFIImageSectionHeader(BinaryReader reader) throws IOException {
		name = reader.readNextAsciiString(8);
		virtualSize = reader.readNextInt();
		virtualAddress = reader.readNextInt();
		rawDataSize = reader.readNextInt();
		rawDataPointer = reader.readNextInt();
		relocationsPointer = reader.readNextInt();
		lineNumbersPointer = reader.readNextInt();
		numRelocations = reader.readNextShort();
		numLineNumbers = reader.readNextShort();
		characteristics = reader.readNextInt();
	}

	/**
	 * Returns the name of the current section.
	 *
	 * @return the name of the current section
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the virtual address for the current section.
	 *
	 * @return the virtual address for the current section
	 */
	public int getVirtualAddress() {
		return virtualAddress;
	}

	/**
	 * Returns the virtual size for the current section.
	 *
	 * @return the virtual size for the current section
	 */
	public int getVirtualSize() {
		return virtualSize;
	}

	/**
	 * Returns whether the current section is executable.
	 *
	 * @return whether the current section is executable
	 */
	public boolean isExecutable() {
		return (characteristics & TerseExecutableConstants.SectionCharacteristics.MEM_EXECUTE)
				!= 0;
	}

	/**
	 * Returns whether the current section is readable.
	 *
	 * @return whether the current section is readable
	 */
	public boolean isReadable() {
		return (characteristics & TerseExecutableConstants.SectionCharacteristics.MEM_READ) != 0;
	}

	/**
	 * Returns whether the current section is writable.
	 *
	 * @return whether the current section is writable
	 */
	public boolean isWritable() {
		return (characteristics & TerseExecutableConstants.SectionCharacteristics.MEM_WRITE) != 0;
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("efi_image_section_hdr_t", 0);
		structure.add(new ArrayDataType(ASCII, 8, 1), "name", null);
		structure.add(DWORD, 4, "virtual_size", null);
		structure.add(DWORD, 4, "virtual_addr", null);
		structure.add(DWORD, 4, "raw_data_size", null);
		structure.add(DWORD, 4, "raw_data_ptr", null);
		structure.add(DWORD, 4, "relocations_ptr", null);
		structure.add(DWORD, 4, "line_numbers_ptr", null);
		structure.add(WORD, 2, "num_relocations", null);
		structure.add(WORD, 2, "num_line_numbers", null);
		structure.add(DWORD, 4, "characteristics", null);
		return structure;
	}
}
