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
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.IOException;

/**
 * Parser for UEFI option ROM images. There are additional fields in the ROM header:
 *
 * <pre>
 *   ROM Header
 *   +---------+------+-------------------------------------------+
 *   | Type    | Size | Description                               |
 *   +---------+------+-------------------------------------------+
 *   | u16     |    2 | Signature (0xAA55, little endian)         |
 *   | u16     |    2 | Image Size (in units of 512 bytes)        |
 *   | u32     |    4 | EFI Signature (0x00000EF1, little endian) |
 *   | u16     |    2 | EFI Subsystem                             |
 *   | u16     |    2 | EFI Machine Type                          |
 *   | u16     |    2 | EFI Compression Type                      |
 *   | u8[8]   |    8 | Reserved                                  |
 *   | u16     |    2 | EFI Image Offset                          |
 *   | u16     |    2 | PCI Data Structure Offset                 |
 *   +---------+------+-------------------------------------------+
 * </pre>
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
	private final short imageSize;
	private final int efiSignature;
	private final short efiSubsystem;
	private final short efiMachineType;
	private final short efiCompressionType;
	private final short efiImageOffset;

	private final ByteProvider provider;

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

		int efiExecutableSize = imageSize * OptionROMConstants.ROM_SIZE_UNIT - efiImageOffset;
		if (efiCompressionType == 1) {
			// Decompress EFI executables that were compressed with the EFI Compression Algorithm.
			reader.setPointerIndex(efiImageOffset);
			byte[] compressedExecutable = reader.readNextByteArray(efiExecutableSize);
			provider = new ByteArrayProvider(EFIDecompressor.decompress(compressedExecutable));
		} else {
			provider = new ByteProviderWrapper(reader.getByteProvider(), efiImageOffset, efiExecutableSize);
		}
	}

	/**
	 * Returns a ByteProvider for the contents of the EFI PE32+ executable. Compressed executables
	 * will be transparently decompressed before returning.
	 *
	 * @return a ByteProvider for the contents of the EFI PE32+ executable
	 */
	@Override
	public ByteProvider getByteProvider() {
		return provider;
	}

	/**
	 * Returns FileAttributes for the current image.
	 *
	 * @return FileAttributes for the current image
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = super.getFileAttributes();
		attributes.add("EFI Subsystem", OptionROMConstants.EFIImageSubsystem.toString(efiSubsystem));
		attributes.add("EFI Machine Type", OptionROMConstants.EFIImageMachineType.toString(efiMachineType));
		attributes.add("EFI Image Compressed", efiCompressionType == 1);
		attributes.add("EFI Image Offset", efiImageOffset);
		return attributes;
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
}
