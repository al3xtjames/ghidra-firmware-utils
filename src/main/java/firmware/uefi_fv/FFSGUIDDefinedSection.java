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

import java.io.IOException;
import java.util.Formatter;
import java.util.UUID;
import java.util.zip.CRC32;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream;

import firmware.common.EFIDecompressor;
import firmware.common.TianoDecompressor;
import firmware.common.UUIDUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.util.BoundedInputStream;
import ghidra.util.Msg;

/**
 * Parser for FFS GUID-defined sections, which have the following specific fields:
 *
 * <pre>
 *   UEFI FFS GUID-Defined Section Header
 *   +------------+------+-------------------------+
 *   | Type       | Size | Description             |
 *   +------------+------+-------------------------+
 *   | efi_guid_t |   16 | Section Definition GUID |
 *   | u16        |    2 | Data Offset             |
 *   | u16        |    2 | Attributes              |
 *   +------------+------+-------------------------+
 * </pre>
 *
 * This header follows the common section header. See FFSSection for additional information.
 * <p>
 * Depending on the Section Definition GUID and the bits set in the Attributes field, the data may be compressed or
 * require other processing.
 *
 * TODO: It would probably be better if this was refactored as FFSGUIDDefinedSectionFactory.
 */
public class FFSGUIDDefinedSection extends FFSSection {
	private static final int GUID_DEFINED_HEADER_SIZE = 20;
	private static final int AMD_ZLIB_HEADER_SIZE = 0x100;
	private static final int AMD_ZLIB_COMPRESSED_SIZE_OFFSET = 0x14;

	// Original header fields
	private final UUID sectionDefinitionGuid;
	private final int dataOffset;
	private final int attributes;

	/**
	 * Constructs a FFSGUIDDefinedSection from a specified BinaryReader and adds it to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public FFSGUIDDefinedSection(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih, GFile parent)
			throws IOException {
		super(reader);

		long baseIndex = reader.getPointerIndex() - super.getHeaderLength();
		sectionDefinitionGuid = UUIDUtils.fromBinaryReader(reader);
		dataOffset = reader.readNextUnsignedShort();
		attributes = reader.readNextUnsignedShort();

		long totalLength = super.getHeaderLength() + super.length();
		int minimumDataOffset = super.getHeaderLength() + GUID_DEFINED_HEADER_SIZE;
		if (dataOffset < minimumDataOffset || dataOffset > totalLength) {
			throw new IOException(String.format(
					"Invalid GUID-defined data offset: %d, expected %d..%d",
					dataOffset, minimumDataOffset, totalLength));
		}
		if (sectionDefinitionGuid.equals(UEFIFFSConstants.CRC32_GUID) &&
				dataOffset < minimumDataOffset + Integer.BYTES) {
			throw new IOException(String.format(
					"Invalid CRC32 GUID-defined data offset: %d, expected at least %d",
					dataOffset, minimumDataOffset + Integer.BYTES));
		}

		// Add this file to the FS.
		GFile fileImpl = fsih.storeFileWithParent(getName(), parent, -1, true, -1, this);

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
			parseNestedSections(sectionReader, uncompressedData.length, fsih, fileImpl);
		} else if (sectionDefinitionGuid.equals(UEFIFFSConstants.LZMA_COMPRESS_GUID)) {
			BoundedInputStream boundedStream = new BoundedInputStream(
					reader.getByteProvider().getInputStream(reader.getPointerIndex()), length());

			try {
				LZMACompressorInputStream inputStream = new LZMACompressorInputStream(boundedStream);
				uncompressedData = inputStream.readAllBytes();

				// Parse the uncompressed section.
				BinaryReader sectionReader = new BinaryReader(
						new ByteArrayProvider(uncompressedData), true);
				parseNestedSections(sectionReader, uncompressedData.length, fsih, fileImpl);
			} catch (IOException e) {
				Msg.error(this, "Failed to extract LZMA compressed section: " + e.getMessage());
				reader.setPointerIndex(baseIndex + getTotalLength());
				return;
			}
		} else if (sectionDefinitionGuid.equals(UEFIFFSConstants.AMD_ZLIB_COMPRESS_GUID) ||
				sectionDefinitionGuid.equals(UEFIFFSConstants.AMD_ZLIB2_COMPRESS_GUID)) {
			// AMD Zlib GUID-defined sections contain a 0x100-byte vendor header followed by
			// the compressed payload. The compressed size is stored at offset 0x14.
			if (length() < AMD_ZLIB_HEADER_SIZE) {
				Msg.error(this, "AMD Zlib section is smaller than its 0x100-byte header");
				reader.setPointerIndex(baseIndex + getTotalLength());
				return;
			}

			long dataIndex = reader.getPointerIndex();
			reader.setPointerIndex(dataIndex + AMD_ZLIB_COMPRESSED_SIZE_OFFSET);
			long compressedSize = reader.readNextUnsignedInt();
			long availableCompressedSize = length() - AMD_ZLIB_HEADER_SIZE;
			if (compressedSize != availableCompressedSize) {
				Msg.error(this, String.format(
						"Invalid AMD Zlib compressed size: header says %d, payload contains %d",
						compressedSize, availableCompressedSize));
				reader.setPointerIndex(baseIndex + getTotalLength());
				return;
			}

			BoundedInputStream boundedStream = new BoundedInputStream(
					reader.getByteProvider().getInputStream(dataIndex + AMD_ZLIB_HEADER_SIZE),
					compressedSize);
			try (InflaterInputStream inputStream = new InflaterInputStream(boundedStream)) {
				uncompressedData = inputStream.readAllBytes();

				BinaryReader sectionReader = new BinaryReader(
						new ByteArrayProvider(uncompressedData), true);
				parseNestedSections(sectionReader, uncompressedData.length, fsih, fileImpl);
			} catch (IOException e) {
				Msg.error(this, "Failed to extract AMD Zlib compressed section: " + e.getMessage());
				reader.setPointerIndex(baseIndex + getTotalLength());
				return;
			}
		} else if (sectionDefinitionGuid.equals(UEFIFFSConstants.CRC32_GUID)) {
			// Read the expected CRC-32 checksum, which is located directly after the attributes
			// field in the section header.
			reader.setPointerIndex(baseIndex + super.getHeaderLength() + 20);
			long expectedChecksum = reader.readNextUnsignedInt();
			reader.setPointerIndex(baseIndex + dataOffset);

			// Read the current GUID-defined section and validate the CRC-32 checksum.
			uncompressedData = reader.readNextByteArray((int) length());
			CRC32 crc32 = new CRC32();
			crc32.update(uncompressedData);
			long checksum = crc32.getValue();
			if (checksum != expectedChecksum) {
				Msg.warn(this, String.format("CRC-32 checksum mismatch: expected %X, got %X",
						expectedChecksum, checksum));
			}

			// Parse the data in the current GUID-defined section.
			BinaryReader sectionReader = new BinaryReader(
					new ByteArrayProvider(uncompressedData), true);
			parseNestedSections(sectionReader, uncompressedData.length, fsih, fileImpl);
		} else if ((attributes &
				UEFIFFSConstants.DefinedSectionAttributes.PROCESSING_REQUIRED) != 0) {
			// The payload cannot be interpreted without a handler for this GUID. Keep it opaque
			// instead of treating compressed/encrypted bytes as nested FFS sections.
			new FFSRawFile(reader, (int) length(), fsih, fileImpl);
		} else {
			// No additional processing is required, so parse the payload as nested sections.
			parseNestedSections(reader, length(), fsih, fileImpl);
		}

		reader.setPointerIndex(baseIndex + getTotalLength());
	}

	/**
	 * Parses all nested sections within a GUID-defined section and adds them to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the BinaryReader for reading the current GUID-defined section
	 * @param length the length of the current GUID-defined section
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	private static void parseNestedSections(BinaryReader reader, long length,
			FileSystemIndexHelper<UEFIFile> fsih, GFile parent) throws IOException {
		long baseIndex = reader.getPointerIndex();
		long maxIndex = baseIndex + length;
		long currentIndex = baseIndex;
		while (currentIndex < maxIndex) {
			long remaining = maxIndex - currentIndex;
			try {
				long sectionLength = getNestedSectionLength(reader, currentIndex, remaining);
				long sectionEnd = currentIndex + sectionLength;

				FFSSectionFactory.parseSection(reader, fsih, parent);
				if (reader.getPointerIndex() > sectionEnd) {
					throw new IOException(String.format(
							"Nested section parser consumed %d bytes, declared size is %d",
							reader.getPointerIndex() - currentIndex, sectionLength));
				}

				// The section header is authoritative for where the next aligned section starts.
				reader.setPointerIndex(sectionEnd);
			} catch (IOException e) {
				reader.setPointerIndex(currentIndex);
				new FFSRawFile(reader, (int) remaining, fsih, parent);
				return;
			}

			long alignedIndex = (reader.getPointerIndex() + 3) & ~3L;
			currentIndex = Math.min(alignedIndex, maxIndex);
			reader.setPointerIndex(currentIndex);
		}
	}

	/**
	 * Reads and validates the declared total length of a nested FFS section without advancing the
	 * reader. This prevents a malformed child section from escaping the bounds of its parent.
	 */
	private static long getNestedSectionLength(BinaryReader reader, long index, long remaining)
			throws IOException {
		if (remaining < UEFIFFSConstants.FFS_SECTION_HEADER_SIZE) {
			throw new IOException("Nested section is smaller than the common section header");
		}

		byte[] sizeBytes =
			reader.getByteProvider().readBytes(index, UEFIFFSConstants.FFS_SECTION_SIZE_LENGTH);
		long sectionLength =
			(sizeBytes[0] & 0xffL) | ((sizeBytes[1] & 0xffL) << 8) | ((sizeBytes[2] & 0xffL) << 16);
		long headerLength = UEFIFFSConstants.FFS_SECTION_HEADER_SIZE;

		if (sectionLength == UEFIFFSConstants.FFS_SECTION2_IS_USED) {
			headerLength += Integer.BYTES;
			if (remaining < headerLength) {
				throw new IOException("Nested extended section is smaller than its header");
			}
			sectionLength = Integer.toUnsignedLong(
				reader.readInt(index + UEFIFFSConstants.FFS_SECTION_HEADER_SIZE));
		}

		if (sectionLength < headerLength || sectionLength > remaining) {
			throw new IOException(String.format(
					"Invalid nested section size: %d, expected %d..%d",
					sectionLength, headerLength, remaining));
		}

		return sectionLength;
	}

	/**
	 * Returns an InputStream for the contents of the current GUID-defined section. This will
	 * return null, as it shouldn't be possible to call this; GUID-defined sections are added to
	 * the FS as directories.
	 *
	 * @return an InputStream for the contents of the current GUID-defined section
	 */
	@Override
	public ByteProvider getByteProvider() {
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
	 * Returns FileAttributes for the current GUID-defined section.
	 *
	 * @return FileAttributes for the current GUID-defined section
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = super.getFileAttributes();
		attributes.add("Section Definition GUID", sectionDefinitionGuid.toString());
		attributes.add("Data Offset", dataOffset);
		attributes.add("Attributes", String.format("%#x", this.attributes));
		return attributes;
	}
}
