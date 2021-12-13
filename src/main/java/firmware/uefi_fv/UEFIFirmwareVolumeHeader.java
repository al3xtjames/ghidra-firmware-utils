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

import firmware.common.UUIDUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Parser for UEFI Firmware Volumes.
 * <p>
 * UEFI firmware volumes begin with the following header:
 *
 * <pre>
 *   UEFI Firmware Volume Header
 *   +-----------------------+------+-------------------------------------------------------------+
 *   | Type                  | Size | Description                                                 |
 *   +-----------------------+------+-------------------------------------------------------------+
 *   | u8                    |   16 | Reset Vector (0x00 bytes)                                   |
 *   | efi_guid_t            |   16 | File System GUID                                            |
 *   | u64                   |    8 | Size                                                        |
 *   | char[4]               |    4 | Signature ("_FVH")                                          |
 *   | u32                   |    4 | Attributes                                                  |
 *   | u16                   |    2 | Header Size (72)                                            |
 *   | u16                   |    2 | Checksum                                                    |
 *   | u16                   |    2 | Extended Header Offset (only for rev 2, otherwise Reserved) |
 *   | u8                    |    1 | Reserved                                                    |
 *   | u8                    |    1 | Revision                                                    |
 *   | efi_fv_block_map_t[]  |  var | Block Map                                                   |
 *   +-----------------------+------+-------------------------------------------------------------+
 * </pre>
 *
 * The Block Map field is unused by this parser. It has the following structure:
 *
 * <pre>
 *   UEFI Firmware Volume Block Map
 *   +------+------+------------------+
 *   | Type | Size | Description      |
 *   +------+------+------------------+
 *   | u32  |    4 | Number of Blocks |
 *   | u32  |    4 | Block Size       |
 *   +------+------+------------------+
 * </pre>
 *
 * The Block Map array is terminated by a Block Map entry with Number of Blocks and Block Size set to 0.
 *
 * The Extended Header Offset field is relative to the start of firmware volume header; it has the following structure:
 *
 * <pre>
 *   UEFI Firmware Volume Extended Header
 *   +------------+------+----------------------+
 *   | Type       | Size | Description          |
 *   +------------+------+----------------------+
 *   | efi_guid_t |   16 | Firmware Volume Name |
 *   | u32        |    4 | Extended Header Size |
 *   +------------+------+----------------------+
 * </pre>
 *
 * Each firmware volume contains a number of UEFI Firmware File System (FFS) files, which may be aligned depending on
 * the bits set in the Attributes field of the UEFI Firmware Volume header.
 * <p>
 * See UFSIFFSFile and UEFIFFSv3File for information regarding the FFS file header fields.
 */
public class UEFIFirmwareVolumeHeader implements UEFIFile {

	/**
	 * Finds the position of the next UEFIFirmwareVolumeHeader.
	 *
	 * @param provider {@link ByteProvider} to read
	 * @param startOffset offset (inclusive) to start scanning at
	 * @return position of the start of the found {@link UEFIFirmwareVolumeHeader}, or -1 if not found
	 * @throws IOException if IO error
	 * @throws CancelledException
	 */
	public static long findNext(ByteProvider provider, long startOffset, TaskMonitor monitor)
			throws IOException, CancelledException {
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(startOffset);
		long eofPos = provider.length() - UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE_LEN;
		long signaturePosition;
		while ((signaturePosition = reader.getPointerIndex()) < eofPos) {
			monitor.checkCanceled();
			monitor.setProgress(signaturePosition);

			int signature = reader.readNextInt();
			if (signaturePosition >= SIGNATURE_OFFSET &&
					signature == UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE_LE) {
				long endOfHeader = signaturePosition - SIGNATURE_OFFSET +
						UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_MIN_SIZE;
				if (endOfHeader >= provider.length()) {
					return -1;
				}

				Msg.debug(UEFIFirmwareVolumeHeader.class,
					String.format("Found _FVH signature at 0x%X", signaturePosition));
				return signaturePosition - SIGNATURE_OFFSET;
			}
		}

		return -1;
	}

	private static final int SIGNATURE_OFFSET = 40;

	// Original header fields
	private final byte[] zeroVector;
	private final UUID fileSystemGuid;
	private final long size;
	private final int signature;
	private final int attributes;
	private final short headerSize;
	private final short checksum;
	private final short extendedHeaderOffset;
	private final byte revision;

	// Extended header fields
	private UUID fvName;
	private int extendedHeaderSize;

	private final long baseIndex;
	private final boolean checksumValid;

	/**
	 * Constructs a UEFIFirmwareVolumeHeader from a specified BinaryReader and adds it to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public UEFIFirmwareVolumeHeader(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih, GFile parent,
			boolean nested) throws IOException {
		baseIndex = reader.getPointerIndex();
		zeroVector = reader.readNextByteArray(16);

		fileSystemGuid = UUIDUtils.fromBinaryReader(reader);
		size = reader.readNextLong();
		if (size < UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_MIN_SIZE) {
			throw new IOException("Not a valid UEFI FV header");
		}

		signature = reader.readNextInt();
		if (signature != UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE_LE) {
			throw new IOException("Not a valid UEFI FV Header");
		}

		attributes = reader.readNextInt();
		headerSize = reader.readNextShort();
		if (headerSize < UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_MIN_SIZE || headerSize > size ||
				headerSize % 2 != 0) {
			throw new IOException("Not a valid UEFI FV Header");
		}

		checksum = reader.readNextShort();
		extendedHeaderOffset = reader.readNextShort();
		if (extendedHeaderOffset > size - UEFIFirmwareVolumeConstants.UEFI_FV_EXT_HEADER_SIZE) {
			throw new IOException("Not a valid UEFI FV Header");
		}

		// Skip the Reserved field.
		reader.setPointerIndex(reader.getPointerIndex() + 1);
		revision = reader.readNextByte();
		if (revision != 1 && revision != 2) {
			throw new IOException("Not a valid UEFI FV Header");
		}

		// Read the extended header fields (if present).
		long bodyIndex;
		if (revision == 2 && extendedHeaderOffset > 0) {
			reader.setPointerIndex(baseIndex + extendedHeaderOffset);
			fvName = UUIDUtils.fromBinaryReader(reader);
			extendedHeaderSize = reader.readNextInt();
			if (extendedHeaderOffset + extendedHeaderSize > size) {
				throw new IOException("Not a valid UEFI FV Header");
			}

			bodyIndex = baseIndex + extendedHeaderOffset + extendedHeaderSize;
		} else {
			bodyIndex = baseIndex + headerSize;
		}

		// Retrieve the current volume's alignment.
		int alignment = 8;
		if (revision == 1) {
			alignment = 1 << ((attributes & UEFIFirmwareVolumeConstants.Attributes.ALIGNMENT));
		}
		else if (revision == 2) {
			alignment = 1 << ((attributes & UEFIFirmwareVolumeConstants.AttributesV2.ALIGNMENT) >> 16);
		}

		if (alignment < 8) {
			alignment = 8;
		}

		// Calculate the checksum.
		int calculatedChecksum = 0;
		reader.setPointerIndex(baseIndex);
		for (int i = 0; i < headerSize; i += 2) {
			calculatedChecksum += reader.readNextUnsignedShort();
		}

		checksumValid = (calculatedChecksum & 0xFFFF) == 0;
		reader.setPointerIndex(bodyIndex);

		// Add this firmware volume as a subdirectory in the current FS.
		GFile fileImpl = fsih.storeFileWithParent(
				UEFIFirmwareVolumeFileSystem.getFSFormattedName(this, parent, fsih), parent, -1, true, -1, this);

		// Ignore NVRAM volumes - add the contents as a raw file, and skip FFS file parsing.
		if (fileSystemGuid.equals(UEFIFirmwareVolumeConstants.EFI_SYSTEM_NV_DATA_FV_GUID)) {
			new FFSRawFile(reader, (int) size - UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_MIN_SIZE, fsih, fileImpl);
		}
		else {
			// Read the files in the current firmware volume.
			while (reader.getPointerIndex() < baseIndex + size) {
				if (nested) {
					// Nested firmware volumes are also aligned to an 8 byte boundary; however,
					// this is relative to the start of the nested firmware volume.
					reader.setPointerIndex(reader.getPointerIndex() - baseIndex);
					reader.align(8);
					reader.setPointerIndex(reader.getPointerIndex() + baseIndex);
				}
				else {
					// FFS files within a firmware volume are aligned to an 8 byte boundary.
					reader.align(8);
				}

				try {
					UEFIFFSFile file = new UEFIFFSFile(reader, fsih, fileImpl);
				}
				catch (IOException e) {
					break;
				}
			}
		}

		// Seek over the entire firmware volume.
		reader.setPointerIndex(baseIndex + size);
	}

	/**
	 * Returns the name of the current firmware volume.
	 *
	 * @return the name of the current firmware volume
	 */
	@Override
	public String getName() {
		if (fvName != null) {
			return UUIDUtils.getName(fvName);
		}

		return UUIDUtils.getName(fileSystemGuid);
	}

	/**
	 * Returns the length of the current firmware volume.
	 *
	 * @return the length of the current firmware volume
	 */
	@Override
	public long length() {
		return size;
	}

	/**
	 * Returns FileAttributes for the current FFS file.
	 *
	 * @return FileAttributes for the current FFS file
	 */
	public FileAttributes getFileAttributes() {
		FileAttributes attributes = new FileAttributes();
		attributes.add(FileAttributeType.NAME_ATTR, getName());
		attributes.add(FileAttributeType.SIZE_ATTR, size);
		attributes.add("Base", String.format("%#x", baseIndex));
		attributes.add("File System GUID", fileSystemGuid.toString());
		attributes.add("Attributes", String.format("%#x", this.attributes));
		attributes.add("Header Size", headerSize);
		attributes.add("Header Checksum", String.format("%#x (%s)", checksum, checksumValid ? "valid" : "invalid"));
		attributes.add("Revision", revision);
		if (revision == 2 && extendedHeaderOffset > 0) {
			attributes.add("Name GUID", fvName.toString());
			attributes.add("Extended Header Size", extendedHeaderSize);
		}

		return attributes;
	}
}
