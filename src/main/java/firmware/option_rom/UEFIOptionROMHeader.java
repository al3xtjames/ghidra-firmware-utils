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

package firmware.option_rom;

import firmware.common.EFIDecompressor;
import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Formatter;

/**
 * Parser for UEFI option ROM images. There are additional fields in the ROM header:
 *
 *   ROM Header
 *   +---------+--------------------------------------------------+
 *   | Type    | Size | Description                               |
 *   +---------+--------------------------------------------------+
 *   | u16     |    2 | Signature (0xAA55, little endian)         |
 *   | u16     |    2 | Image Size (in units of 512 bytes)        |
 *   | u32     |    4 | EFI Signature (0x00000EF1, little endian) |
 *   | u16     |    2 | EFI Subsystem                             |
 *   | u16     |    2 | EFI Machine Type                          |
 *   | u16     |    2 | EFI Compression Type                      |
 *   | u8[8]   |    8 | Reserved                                  |
 *   | u16     |    2 | EFI Image Offset                          |
 *   | u16     |    2 | PCI Data Structure Offset                 |
 *   +---------+--------------------------------------------------+
 *
 * See OptionROMConstants for possible EFI Subsystem and Machine Type values.
 *
 * The EFI Image Offset field in the ROM header is used to locate the EFI PE32+ executable. If the
 * EFI Compression Type field is set to 1, the PE32+ executable is compressed with the EFI
 * Compression Algorithm, which is a combination of the LZ77 algorithm and Huffman coding. The
 * EFIDecompressor class is used to handle compressed images.
 */
public class UEFIOptionROMHeader extends OptionROMHeader {
	// Original header fields
	private short imageSize;
	private int efiSignature;
	private short efiSubsystem;
	private short efiMachineType;
	private short efiCompressionType;
	private short efiImageOffset;

	// The EFI PE32+ executable stored in the option ROM
	// May be compressed with the EFI Compression Algorithm
	private byte[] efiImage;

	/**
	 * Constructs a UEFIOptionROMHeader from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public UEFIOptionROMHeader(BinaryReader reader) throws IOException {
		super(reader);
		byte codeType = getPCIRHeader().getCodeType();
		if (codeType != OptionROMConstants.CodeType.EFI) {
			throw new IOException("Code type mismatch: expected EFI (3), got " +
					OptionROMConstants.CodeType.toString(codeType) + " (" + codeType + ')');
		}

		reader.setPointerIndex(0x2);
		imageSize = reader.readNextShort();
		efiSignature = reader.readNextInt();
		if (efiSignature != OptionROMConstants.EFI_SIGNATURE) {
			throw new IOException("Not a valid EFI PCI option ROM header");
		}

		efiSubsystem = reader.readNextShort();
		efiMachineType = reader.readNextShort();
		efiCompressionType = reader.readNextShort();
		reader.setPointerIndex(0x16);
		efiImageOffset = reader.readNextShort();
		reader.setPointerIndex(efiImageOffset);
		int efiExecutableSize = imageSize * OptionROMConstants.ROM_SIZE_UNIT - efiImageOffset;
		efiImage = reader.readNextByteArray(efiExecutableSize);
	}

	/**
	 * Returns a ByteArrayInputStream for the contents of the EFI PE32+ executable. Compressed
	 * executables will be transparently decompressed before returning.
	 *
	 * @return a ByteArrayInputStream for the contents of the EFI PE32+ executable
	 */
	@Override
	public ByteArrayInputStream getImageStream() {
		if (efiCompressionType == 1) {
			return new ByteArrayInputStream(EFIDecompressor.decompress(efiImage));
		} else {
			return new ByteArrayInputStream(efiImage);
		}
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("uefi_option_rom_header_t", 0);
		structure.add(WORD, 2,"signature", null);
		structure.add(WORD, 2, "image_size", null);
		structure.add(DWORD, 4, "efi_signature", null);
		structure.add(WORD, 2, "efi_subsystem", null);
		structure.add(WORD, 2, "efi_machine_type", null);
		structure.add(WORD, 2, "efi_compression_type", null);
		structure.add(new ArrayDataType(BYTE, 0x8, 1), "reserved", null);
		structure.add(POINTER, 2,"efi_image_offset", null);
		structure.add(POINTER, 2, "pcir_offset", null);
		return structure;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("EFI Subsystem: %s\n",
				OptionROMConstants.EFIImageSubsystem.toString(efiSubsystem));
		formatter.format("EFI Machine Type: %s\n",
				OptionROMConstants.EFIImageMachineType.toString(efiMachineType));
		formatter.format("EFI Image Compression: %b\n", efiCompressionType == 1);
		formatter.format("EFI Image Offset: 0x%X\n", efiImageOffset);
		formatter.format("%s\n", super.toString());
		return formatter.toString();
	}
}
