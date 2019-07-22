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

package firmware.uefi_fv;

import firmware.common.EFIDecompressor;
import firmware.common.TianoDecompressor;
import firmware.common.UUIDUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.formats.gfilesystem.GFile;
import ghidra.util.BoundedInputStream;
import ghidra.util.Msg;
import org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.util.Formatter;
import java.util.UUID;

/**
 * Parser for FFS GUID-defined sections, which have the following specific fields:
 *
 *   UEFI FFS GUID-Defined Section Header
 *   +------------+------+-------------------------+
 *   | Type       | Size | Description             |
 *   +------------+------+-------------------------+
 *   | efi_guid_t |   16 | Section Definition GUID |
 *   | u16        |    2 | Data Offset             |
 *   | u16        |    2 | Attributes              |
 *   +------------+------+-------------------------+
 *
 * This header follows the common section header. See FFSSection for additional information.
 * Depending on the Section Definition GUID and the bits set in the Attributes field, the data
 * may be compressed or require other processing.
 */
public class FFSGUIDDefinedSection extends FFSSection {
	// Original header fields
	private UUID sectionDefinitionGuid;
	private short dataOffset;
	private short attributes;

	/**
	 * Constructs a FFSGUIDDefinedSection from a specified BinaryReader and adds it to a specified
	 * UEFIFirmwareVolumeFileSystem.
	 *
	 * @param reader the specified BinaryReader
	 * @param fs     the specified UEFIFirmwareVolumeFileSystem
	 * @param parent the parent directory in the specified UEFIFirmwareVolumeFileSystem
	 */
	public FFSGUIDDefinedSection(BinaryReader reader, UEFIFirmwareVolumeFileSystem fs,
								 GFile parent) throws IOException {
		super(reader);

		long baseIndex = reader.getPointerIndex() - UEFIFFSConstants.FFS_SECTION_HEADER_SIZE;
		sectionDefinitionGuid = UUIDUtils.fromBinaryReader(reader);
		dataOffset = reader.readNextShort();
		attributes = reader.readNextShort();

		// Add this file to the FS.
		GFile fileImpl = fs.addFile(parent, this, getName(), true);

		// Try to extract compressed sections.
		reader.setPointerIndex(baseIndex + dataOffset);
		byte[] uncompressedData;
		if (sectionDefinitionGuid.equals(UEFIFFSConstants.TIANO_COMPRESS_GUID)) {
			// STANDARD_COMPRESSION indicates that either the EFI Compression Algorithm or the
			// Tiano Compression Algorithm was used. Attempt to extract the compressed data with
			// both decompressors.
			byte[] compressedData = reader.readNextByteArray((int) length());
			uncompressedData = EFIDecompressor.decompress(compressedData);
			if (uncompressedData == null) {
				uncompressedData = TianoDecompressor.decompress(compressedData);
				if (uncompressedData == null) {
					Msg.error(this, "Failed to extract compressed section");
					reader.setPointerIndex(baseIndex + getTotalLength());
					return;
				}
			}

			// Parse the uncompressed section.
			BinaryReader sectionReader = new BinaryReader(
				new ByteArrayProvider(uncompressedData), true);
			parseNestedSections(sectionReader, uncompressedData.length, fs, fileImpl);
		} else if (sectionDefinitionGuid.equals(UEFIFFSConstants.LZMA_COMPRESS_GUID)) {
			BoundedInputStream boundedStream = new BoundedInputStream(
				reader.getByteProvider().getInputStream(reader.getPointerIndex()),
				length());

			try {
				LZMACompressorInputStream inputStream = new LZMACompressorInputStream(boundedStream);
				uncompressedData = inputStream.readAllBytes();

				// Parse the uncompressed section.
				BinaryReader sectionReader = new BinaryReader(
					new ByteArrayProvider(uncompressedData), true);
				parseNestedSections(sectionReader, uncompressedData.length, fs, fileImpl);
			} catch (IOException e) {
				Msg.error(this, "Failed to extract LZMA compressed section: " +
						e.getMessage());
				reader.setPointerIndex(baseIndex + getTotalLength());
				return;
			}
		} else {
			// Parse the data in the current GUID-defined section.
			parseNestedSections(reader, length(), fs, fileImpl);
		}

		reader.setPointerIndex(baseIndex + getTotalLength());
	}

	/**
	 * Parses all nested sections within a GUID-defined section and adds them to a specified
	 * UEFIFirmwareVolumeFileSystem.
	 *
	 * @param reader the BinaryReader for reading the current GUID-defined section
	 * @param length the length of the current GUID-defined section
	 * @param fs     the specified UEFIFirmwareVolumeFileSystem
	 * @param parent the parent directory in the specified UEFIFirmwareVolumeFileSystem
	 */
	private static void parseNestedSections(BinaryReader reader, long length,
			UEFIFirmwareVolumeFileSystem fs, GFile parent) throws IOException {
		long baseIndex = reader.getPointerIndex();
		long maxIndex = baseIndex + length;
		long currentIndex = baseIndex;
		while (currentIndex < maxIndex) {
			// Try to parse each FFS section.
			try {
				FFSSectionFactory.parseSection(reader, fs, parent);
			} catch (IOException e) {
				reader.setPointerIndex(currentIndex);
				new FFSRawFile(reader, (int) (maxIndex - currentIndex), fs, parent);
			}

			reader.align(4);
			currentIndex = reader.getPointerIndex();
		}
	}

	/**
	 * Returns an InputStream for the contents of the current GUID-defined section. This will
	 * return null, as it shouldn't be possible to call this; GUID-defined sections are added to
	 * the FS as directories.
	 *
	 * @return an InputStream for the contents of the current GUID-defined section
	 */
	public InputStream getData() {
		return null;
	}

	/**
	 * Returns the length of the GUID-defined section header.
	 *
	 * @return the length of the GUID-defined section header
	 */
	@Override
	public int getHeaderLength() {
		return dataOffset;
	}

	/**
	 * Returns the name of the current GUID-defined section.
	 *
	 * @return the name of the current GUID-defined section
	 */
	@Override
	public String getName() {
		return super.getName() + " - " + UUIDUtils.getName(sectionDefinitionGuid);
	}

	/**
	 * Returns the length of the body in the current GUID-defined section.
	 *
	 * @return the length of the body in the current GUID-defined section
	 */
	@Override
	public long length() {
		// FFSSection.length() returns the length of the FFS section body. However, we need the
		// length of the entire FFS section (including the header), as dataOffset needs to be
		// subtracted from the length of the entire FFS section.
		return super.length() + super.getHeaderLength() - dataOffset;
	}

	/**
	 * Returns a string representation of the current GUID-defined section.
	 *
	 * @return a string representation of the current GUID-defined section
	 */
	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("%s\n", super.toString());
		formatter.format("Section definition GUID: %s\n", sectionDefinitionGuid.toString());
		formatter.format("Data offset: 0x%X\n", dataOffset);
		formatter.format("Attributes: 0x%X", attributes);
		return formatter.toString();
	}
}
