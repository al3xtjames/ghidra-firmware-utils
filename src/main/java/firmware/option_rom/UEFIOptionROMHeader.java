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
import ghidra.util.exception.DuplicateNameException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Formatter;

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

	public UEFIOptionROMHeader(BinaryReader reader) throws IOException {
		super(reader);
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

	@Override
	public ByteArrayInputStream getImageStream() {
		if (efiCompressionType == 1) {
			return new ByteArrayInputStream(EFIDecompressor.decompress(efiImage));
		} else {
			return new ByteArrayInputStream(efiImage);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("uefi_option_rom_header", 0);
		structure.add(WORD, "signature", null);
		structure.add(WORD, "image_size", null);
		structure.add(DWORD, "efi_signature", null);
		structure.add(WORD, "efi_subsystem", null);
		structure.add(WORD, "efi_machine_type", null);
		structure.add(WORD, "efi_compression_type", null);
		structure.add(new ArrayDataType(BYTE, 0x8, BYTE.getLength()), "reserved", null);
		structure.add(WORD, "efi_image_offset", null);
		structure.add(WORD, "pcir_offset", null);
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
