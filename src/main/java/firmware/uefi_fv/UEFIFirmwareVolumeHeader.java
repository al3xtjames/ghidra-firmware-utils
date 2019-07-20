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

import firmware.common.UUIDUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.formats.gfilesystem.GFile;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Formatter;
import java.util.UUID;

/**
 * Parser for UEFI Firmware Volumes.
 *
 * UEFI firmware volumes begin with the following header:
 *
 *   UEFI Firmware Volume Header
 *   +-----------------------+------+-------------------------------------------------------------+
 *   | Type                  | Size | Description                                                 |
 *   +-----------------------+------+-------------------------------------------------------------+
 *   | u8                    |    1 | Reset Vector (0x00 bytes)                                   |
 *   | efi_guid_t            |   16 | File System GUID                                            |
 *   | u64                   |    8 | Size                                                        |
 *   | char[4]               |    4 | Signature ("_FVH")                                          |
 *   | u32                   |    4 | Attributes                                                  |
 *   | u16                   |    2 | Header Size (72)                                            |
 *   | u16                   |    2 | Checksum                                                    |
 *   | u16                   |    2 | Extended Header Offset (only for rev 2, otherwise Reserved) |
 *   | u8                    |    1 | Reserved                                                    |
 *   | u8                    |    1 | Revision                                                    |
 *   | efi_fv_block_map_t[2] |   16 | Block Map                                                   |
 *   +--------------------+------+----------------------------------------------------------------+
 *
 * The Block Map field is unused by this parser. It has the following structure:
 *
 *   UEFI Firmware Volume Block Map
 *   +------+------+------------------+
 *   | Type | Size | Description      |
 *   +------+------+------------------+
 *   | u32  |    4 | Number of Blocks |
 *   | u32  |    4 | Block Size       |
 *   +------+------+------------------+
 *
 * Each firmware volume contains a number of UEFI Firmware File System (FFS) files, which may be
 * aligned depending on the bits set in the Attributes field of the UEFI Firmware Volume header.
 * See UFSIFFSFile and UEFIFFSv3File for information regarding the FFS file header fields.
 */
public class UEFIFirmwareVolumeHeader implements UEFIFile {
	// Original header fields
	private byte[] zeroVector;
	private UUID fileSystemGuid;
	private long size;
	private String signature;
	private int attributes;
	private short headerSize;
	private short checksum;
	private short extendedHeaderOffset;
	private byte revision;

	private long baseIndex;

	/**
	 * Constructs a UEFIFirmwareVolumeHeader from a specified BinaryReader and adds it to a
	 * specified UEFIFirmwareVolumeFileSystem.
	 *
	 * @param reader the specified BinaryReader
	 * @param fs	 the specified UEFIFirmwareVolumeFileSystem
	 * @param parent the parent directory in the specified UEFIFirmwareVolumeFileSystem
	 */
	public UEFIFirmwareVolumeHeader(BinaryReader reader, UEFIFirmwareVolumeFileSystem fs,
			GFile parent, boolean nested) throws IOException {
		baseIndex = reader.getPointerIndex();
		zeroVector = reader.readNextByteArray(16);

		fileSystemGuid = UUIDUtils.fromBinaryReader(reader);
		size = reader.readNextLong();
		if (size <= UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_SIZE) {
			throw new IOException("Not a valid UEFI FV header");
		}

		signature = reader.readNextAsciiString(
				UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE.length());
		if (!signature.equals(UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE)) {
			throw new IOException("Not a valid UEFI FV Header");
		}

		attributes = reader.readNextInt();
		headerSize = reader.readNextShort();
		checksum = reader.readNextShort();
		extendedHeaderOffset = reader.readNextShort();

		// Skip the Reserved field.
		reader.setPointerIndex(reader.getPointerIndex() + 1);
		revision = reader.readNextByte();

		// Skip the FvBlockMap field.
		reader.setPointerIndex(reader.getPointerIndex() + 16);

		if (revision == 2 && extendedHeaderOffset > 0) {
			// The extended header structure consists of a EFI GUID followed by the size of the
			// header (stored as u32).
			reader.setPointerIndex(baseIndex + extendedHeaderOffset + 16);
			int extendedHeaderSize = reader.readNextInt();
			reader.setPointerIndex(baseIndex + extendedHeaderOffset + extendedHeaderSize);
		}

		// Retrieve the current volume's alignment.
		int alignment = 8;
		if (revision == 1) {
			alignment = 1 << ((attributes & UEFIFirmwareVolumeConstants.Attributes.ALIGNMENT));
		} else if (revision == 2) {
			alignment = 1 << ((attributes & UEFIFirmwareVolumeConstants.AttributesV2.ALIGNMENT) >> 16);
		} else {
			Msg.warn(this, "Unknown FV header revision: " + revision);
		}

		if (alignment < 8) {
			alignment = 8;
		}

		// Add this firmware volume as a subdirectory in the current FS.
		GFile fileImpl = fs.addFile(parent, this, true);

		// Ignore NVRAM volumes - add the contents as a raw file, and skip FFS file parsing.
		if (fileSystemGuid.equals(UEFIFirmwareVolumeConstants.EFI_SYSTEM_NV_DATA_FV_GUID)) {
			new FFSRawFile(reader, (int) size - UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_SIZE,
					fs, fileImpl);
		} else {
			// Read the files in the current firmware volume.
			while (reader.getPointerIndex() < baseIndex + size) {
				if (nested) {
					// Nested firmware volumes are also aligned to an 8 byte boundary; however,
					// this is relative to the start of the nested firmware volume.
					reader.setPointerIndex(reader.getPointerIndex() - baseIndex);
					reader.align(8);
					reader.setPointerIndex(reader.getPointerIndex() + baseIndex);
				} else {
					// FFS files within a firmware volume are aligned to an 8 byte boundary.
					reader.align(8);
				}

				long originalIndex = reader.getPointerIndex();
				try {
					UEFIFFSFile file = new UEFIFFSFile(reader, fs, fileImpl);
				} catch (IOException e) {
					break;
				}
			}
		}

		// Seek over the entire firmware volume.
		reader.setPointerIndex(baseIndex + size);
	}

	/**
	 * Returns the file system GUID for the current firmware volume.
	 *
	 * @return the file system GUID for the current firmware volume
	 */
	public UUID getGUID() {
		return fileSystemGuid;
	}

	/**
	 * Returns the name of the current firmware volume.
	 *
	 * @return the name of the current firmware volume
	 */
	public String getName() {
		return UUIDUtils.getName(fileSystemGuid);
	}

	/**
	 * Returns the length of the current firmware volume.
	 *
	 * @return the length of the current firmware volume
	 */
	public long length() {
		return size;
	}

	/**
	 * Returns a string representation of the current firmware volume.
	 *
	 * @return a string representation of the current firmware volume
	 */
	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("Firmware volume base: 0x%X\n", baseIndex);
		formatter.format("Firmware volume FS GUID: %s\n", fileSystemGuid.toString());
		formatter.format("Firmware volume size: 0x%X\n", size);
		formatter.format("Firmware volume attributes: 0x%X\n", attributes);
		formatter.format("Firmware volume header size: 0x%X\n", headerSize);
		formatter.format("Firmware volume revision: %d", revision);
		return formatter.toString();
	}
}
