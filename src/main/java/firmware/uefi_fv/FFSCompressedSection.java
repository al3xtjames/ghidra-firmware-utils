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

import java.io.*;
import java.util.Formatter;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import org.apache.commons.compress.compressors.lzma.LZMACompressorInputStream;

import firmware.common.EFIDecompressor;
import firmware.common.TianoDecompressor;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.util.Msg;

/**
 * Parser for compressed FFS sections, which have the following fields:
 *
 * <pre>
 *   UEFI Compressed Section Header
 *   +------+------+-------------------+
 *   | Type | Size | Description       |
 *   +------+------+-------------------+
 *   | u32  |    4 | Uncompressed Size |
 *   | u8   |    1 | Compression Type  |
 *   +------+------+-------------------+
 * </pre>
 *
 * The header follows the common section header. See FFSSection for additional information. The
 * compressed data immediately follows the compressed section header.
 * <p>
 * A Compression Type value of 0x01 (STANDARD_COMPRESSION) indicates that the section is compressed
 * with the EFI Compression Algorithm or the Tiano Compression Algorithm.
 */
public class FFSCompressedSection extends FFSSection {
	// Original header fields
	private final int uncompressedSize;
	private final byte compressionType;

	/**
	 * Constructs a FFSCompressedSection from a specified BinaryReader and adds it to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public FFSCompressedSection(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih,
			GFile parent) throws IOException {
		super(reader);

		uncompressedSize = reader.readNextInt();
		compressionType = reader.readNextByte();
		byte[] compressedData = reader.readNextByteArray((int) length());

		byte[] uncompressedData;
		switch (compressionType) {
			case UEFIFFSConstants.CompressionType.NOT_COMPRESSED:
				uncompressedData = compressedData;
				break;
			case UEFIFFSConstants.CompressionType.STANDARD_COMPRESSION:
				// STANDARD_COMPRESSION indicates that either the EFI Compression Algorithm or the
				// Tiano Compression Algorithm was used. Attempt to extract the compressed data with
				// both decompressors.
				uncompressedData = EFIDecompressor.decompress(compressedData);
				if (uncompressedData == null) {
					uncompressedData = TianoDecompressor.decompress(compressedData);
					if (uncompressedData == null) {
						Msg.error(this, "Failed to extract compressed section");
						return;
					}
				}

				break;
			case UEFIFFSConstants.CompressionType.CUSTOMIZED_COMPRESSION:
				// CUSTOMIZED_COMPRESSION indicates that LZMA was used.
				try {
					LZMACompressorInputStream inputStream = new LZMACompressorInputStream(
						new ByteArrayInputStream(compressedData));
					uncompressedData = inputStream.readAllBytes();
				} catch (IOException e) {
					Msg.error(this, "Failed to extract LZMA compressed section: " +
							e.getMessage());
					return;
				}

				break;
			default:
				Msg.error(this, "Unknown compression type " + compressionType);
				return;
		}

		// Add this section to the FS.
		GFile fileImpl = fsih.storeFileWithParent(getName(), parent, -1, true, -1, this);

		// Add the uncompressed section to the FS as a file.
		BinaryReader sectionReader = new BinaryReader(new ByteArrayProvider(uncompressedData), true);
		FFSSection section = FFSSectionFactory.parseSection(sectionReader, fsih, fileImpl);
	}

	/**
	 * Returns the compression type for the current compressed section.
	 *
	 * @return the compression type for the current compressed section
	 */
	public byte getCompressionType() {
		return compressionType;
	}

	/**
	 * Returns a ByteProvider for the contents of the current compressed section. This will return
	 * null, as it shouldn't be possible to call this; compressed sections are added to the FS as
	 * directories.
	 *
	 * @return a ByteProvider for the contents of the current compressed section
	 */
	@Override
	public ByteProvider getByteProvider() {
		return null;
	}

	/**
	 * Returns the length of the compressed section header.
	 *
	 * @return the length of the compressed section header
	 */
	@Override
	public int getHeaderLength() {
		return UEFIFFSConstants.FFS_SECTION_HEADER_SIZE + 5;
	}

	/**
	 * Returns the length of the uncompressed section stored within the current compressed section.
	 *
	 * @return the length of the uncompressed section stored within the current compressed section
	 */
	public int getUncompressedSize() {
		return uncompressedSize;
	}

	/**
	 * Returns the length of the body in the current compressed section. This is the compressed
	 * size.
	 *
	 * @return the length of the body in the current compressed section
	 */
	@Override
	public long length() {
		return super.length() - 5;
	}

	/**
	 * Returns FileAttributes for the current compressed section.
	 *
	 * @return FileAttributes for the current compressed section
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add("Uncompressed Size", uncompressedSize);
		attributes.add("Compression Type", UEFIFFSConstants.CompressionType.toString(compressionType));
		return attributes;
	}
}
