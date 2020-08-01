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
 *   | efi_fv_block_map_t[2] |   16 | Block Map                                                   |
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
						UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_SIZE;
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
	private byte[] zeroVector;
	private UUID fileSystemGuid;
	private long size;
	private int signature;
	private int attributes;
	private short headerSize;
	private short checksum;
	private short extendedHeaderOffset;
	private byte revision;

	// Extended header fields
	private UUID fvName;
	private int extendedHeaderSize;

	private long baseIndex;

	/**
	 * Constructs a UEFIFirmwareVolumeHeader from a specified BinaryReader and adds it to a specified
	 * FileSystemIndexHelper.
	 *
	 * @param reader the specified BinaryReader
	 * @param fsih   the specified {@link FileSystemIndexHelper} that handles files
	 * @param parent the parent directory in the specified FileSystemIndexHelper
	 */
	public UEFIFirmwareVolumeHeader(BinaryReader reader, FileSystemIndexHelper<UEFIFile> fsih,
			GFile parent, boolean nested) throws IOException {
		baseIndex = reader.getPointerIndex();
		zeroVector = reader.readNextByteArray(16);

		fileSystemGuid = UUIDUtils.fromBinaryReader(reader);
		size = reader.readNextLong();
		if (size < UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_SIZE) {
			throw new IOException("Not a valid UEFI FV header");
		}

		signature = reader.readNextInt();
		if (signature != UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE_LE) {
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

		// Read the extended header fields (if present).
		if (revision == 2 && extendedHeaderOffset > 0) {
			reader.setPointerIndex(baseIndex + extendedHeaderOffset);
			fvName = UUIDUtils.fromBinaryReader(reader);
			extendedHeaderSize = reader.readNextInt();
			reader.setPointerIndex(baseIndex + extendedHeaderOffset + extendedHeaderSize);
		}

		// Retrieve the current volume's alignment.
		int alignment = 8;
		if (revision == 1) {
			alignment = 1 << ((attributes & UEFIFirmwareVolumeConstants.Attributes.ALIGNMENT));
		}
		else if (revision == 2) {
			alignment =
					1 << ((attributes & UEFIFirmwareVolumeConstants.AttributesV2.ALIGNMENT) >> 16);
		}
		else {
			Msg.warn(this, "Unknown FV header revision: " + revision);
		}

		if (alignment < 8) {
			alignment = 8;
		}

		// Add this firmware volume as a subdirectory in the current FS.
		GFile fileImpl = fsih.storeFileWithParent(
			UEFIFirmwareVolumeFileSystem.getFSFormattedName(this, parent, fsih), parent, -1, true,
			-1, this);

		// Ignore NVRAM volumes - add the contents as a raw file, and skip FFS file parsing.
		if (fileSystemGuid.equals(UEFIFirmwareVolumeConstants.EFI_SYSTEM_NV_DATA_FV_GUID)) {
			new FFSRawFile(reader, (int) size - UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_SIZE,
				fsih, fileImpl);
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
		if (revision == 2 && extendedHeaderOffset > 0) {
			formatter.format("\nFirmware volume name GUID: %s\n", fvName.toString());
			formatter.format("Firmware volume extended header size: 0x%X", extendedHeaderSize);
		}

		return formatter.toString();
	}
}
