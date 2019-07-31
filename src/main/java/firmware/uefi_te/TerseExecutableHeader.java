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
 * Parser for Terse Executable (TE) binaries. TE binaries are a simplified form of PE/COFF
 * executables; fields from the COFF header and optional image headers (including Windows-specific
 * fields) are consolidated into a single header, which has the following fields:
 *
 *   EFI Terse Executable Image Header
 *   +---------------------+------+--------------------------------------------+
 *   | Type                | Size | Description                                |
 *   +---------------------+------+--------------------------------------------+
 *   | char[2]             |    2 | Signature ("VZ")                           |
 *   | u16                 |    2 | Machine Type (same as COFF field)          |
 *   | u8                  |    1 | Number of Sections                         |
 *   | u8                  |    1 | Subsystem (same as Windows-specific field) |
 *   | u16                 |    2 | Stripped Size                              |
 *   | u32                 |    4 | Entry Point Address                        |
 *   | u32                 |    4 | Code Base Address                          |
 *   | u64                 |    8 | Image Base Address                         |
 *   | pe_image_data_dir_t |    8 | Base Relocation Directory (same as PE)     |
 *   | pe_image_data_dir_t |    8 | Debug Directory (same as PE)               |
 *   +---------------------+------+--------------------------------------------+
 *
 * The TE header is immediately followed by an array of section headers; these are standard PE
 * section headers.
 */
public class TerseExecutableHeader implements StructConverter {
	// Original header fields
	private String signature;
	private short machine;
	private byte numSections;
	private byte subsystem;
	private short strippedSize;
	private int entryPointAddress;
	private int codeBase;
	private long imageBase;
	private EFIImageDataDirectory baseRelocationDirectory;
	private EFIImageDataDirectory debugDirectory;
	private EFIImageSectionHeader[] sectionHeaders;

	/**
	 * Constructs a TerseExecutableHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public TerseExecutableHeader(BinaryReader reader) throws IOException {
		// Read the TE header fields.
		signature = reader.readNextAsciiString(
				TerseExecutableConstants.TE_SIGNATURE.length());
		if (!signature.equals(TerseExecutableConstants.TE_SIGNATURE)) {
			throw new IOException("Not a valid Terse Executable");
		}

		machine = reader.readNextShort();
		numSections = reader.readNextByte();
		subsystem = reader.readNextByte();
		strippedSize = reader.readNextShort();
		entryPointAddress = reader.readNextInt();
		codeBase = reader.readNextInt();
		imageBase = reader.readNextLong();
		baseRelocationDirectory = new EFIImageDataDirectory(reader);
		debugDirectory = new EFIImageDataDirectory(reader);

		// Parse the section headers.
		sectionHeaders = new EFIImageSectionHeader[numSections];
		for (int i = 0; i < numSections; i++) {
			sectionHeaders[i] = new EFIImageSectionHeader(reader);
		}
	}

	/**
	 * Returns the entry point address in the current TE header.
	 *
	 * @return the entry point address in the current TE header
	 */
	public int getEntryPointAddress() {
		return entryPointAddress;
	}

	/**
	 * Returns the header offset in the current TE header.
	 *
	 * @return the header offset in the current TE header
	 */
	public int getHeaderOffset() {
		return strippedSize - TerseExecutableConstants.TE_HEADER_SIZE;
	}

	/**
	 * Returns the image base in the current TE header.
	 *
	 * @return the image base in the current TE header
	 */
	public long getImageBase() {
		return imageBase;
	}

	/**
	 * Returns the machine type in the current TE header.
	 *
	 * @return the machine type in the current TE header
	 */
	public short getMachineType() {
		return machine;
	}

	/**
	 * Returns the number of sections in the current TE header.
	 *
	 * @return the number of sections in the current TE header
	 */
	public byte getNumSections() {
		return numSections;
	}

	/**
	 * Returns the section headers in the current TE header.
	 *
	 * @return the section headers in the current TE header
	 */
	public EFIImageSectionHeader[] getSections() {
		return sectionHeaders;
	}

	/**
	 * Returns the subsystem in the current TE header.
	 *
	 * @return the subsystem in the current TE header.
	 */
	public short getSubsystem() {
		return subsystem;
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("efi_image_te_hdr_t", 0);
		structure.add(new ArrayDataType(ASCII, TerseExecutableConstants.TE_SIGNATURE.length(), 1),
				"signature", null);
		structure.add(WORD, 2, "machine", null);
		structure.add(BYTE, 1, "num_sections", null);
		structure.add(BYTE, 1, "subsystem", null);
		structure.add(WORD, 2, "stripped_size", null);
		structure.add(DWORD, 4, "entry_point_addr", null);
		structure.add(DWORD, 4, "code_base", null);
		structure.add(QWORD, 8, "image_base", null);
		structure.add(baseRelocationDirectory.toDataType(), "base_relocation_data_dir", null);
		structure.add(debugDirectory.toDataType(), "debug_data_dir", null);
		return structure;
	}
}
