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

import java.util.UUID;

/**
 * Various UEFI Firmware Volume constants.
 */
public final class UEFIFirmwareVolumeConstants {
	// UEFI Firmware Volume signature
	public static final String UEFI_FV_SIGNATURE = "_FVH";
	public static final int UEFI_FV_SIGNATURE_LE = 0x4856465f;
	public static final int UEFI_FV_SIGNATURE_LEN = 4;

	// Size of the UEFI Firmware Volume Header structure
	public static final int UEFI_FV_HEADER_SIZE = 72;

	// UEFI Firmware Volume attributes (legacy)
	public static final class Attributes {
		public static final int ALIGNMENT = 0x0000001F;
		public static final int FIXED = 0x00000100;
		public static final int MEMORY_MAPPED = 0x00000200;
	}

	// UEFI Firmware Volume attributes
	public static final class AttributesV2 {
		public static final int READ_DISABLED_CAP = 0x00000001;
		public static final int READ_ENABLED_CAP = 0x00000002;
		public static final int READ_STATUS = 0x00000004;
		public static final int WRITE_DISABLED_CAP = 0x00000008;
		public static final int WRITE_ENABLED_CAP = 0x00000010;
		public static final int WRITE_STATUS = 0x00000020;
		public static final int LOCK_CAP = 0x00000040;
		public static final int LOCK_STATUS = 0x00000080;
		public static final int STICKY_WRITE = 0x00000200;
		public static final int MEMORY_MAPPED = 0x00000400;
		public static final int ERASE_POLARITY = 0x00000800;
		public static final int READ_LOCK_CAP = 0x00001000;
		public static final int READ_LOCK_STATUS = 0x00002000;
		public static final int WRITE_LOCK_CAP = 0x00004000;
		public static final int WRITE_LOCK_STATUS = 0x00008000;
		public static final int ALIGNMENT = 0x001F0000;
		public static final int WEAK_ALIGNMENT = 0x80000000;
		public static final int ALIGNMENT_1 = 0x00000000;
		public static final int ALIGNMENT_2 = 0x00010000;
		public static final int ALIGNMENT_4 = 0x00020000;
		public static final int ALIGNMENT_8 = 0x00030000;
		public static final int ALIGNMENT_16 = 0x00040000;
		public static final int ALIGNMENT_32 = 0x00050000;
		public static final int ALIGNMENT_64 = 0x00060000;
		public static final int ALIGNMENT_128 = 0x00070000;
		public static final int ALIGNMENT_256 = 0x00080000;
		public static final int ALIGNMENT_512 = 0x00090000;
		public static final int ALIGNMENT_1K = 0x000A0000;
		public static final int ALIGNMENT_2K = 0x000B0000;
		public static final int ALIGNMENT_4K = 0x000C0000;
		public static final int ALIGNMENT_8K = 0x000D0000;
		public static final int ALIGNMENT_16K = 0x000E0000;
		public static final int ALIGNMENT_32K = 0x000F0000;
		public static final int ALIGNMENT_64K = 0x00100000;
		public static final int ALIGNMENT_128K = 0x00110000;
		public static final int ALIGNMENT_256K = 0x00120000;
		public static final int ALIGNMENT_512K = 0x00130000;
		public static final int ALIGNMENT_1M = 0x00140000;
		public static final int ALIGNMENT_2M = 0x00150000;
		public static final int ALIGNMENT_4M = 0x00160000;
		public static final int ALIGNMENT_8M = 0x00170000;
		public static final int ALIGNMENT_16M = 0x00180000;
		public static final int ALIGNMENT_32M = 0x00190000;
		public static final int ALIGNMENT_64M = 0x001A0000;
		public static final int ALIGNMENT_128M = 0x001B0000;
		public static final int ALIGNMENT_256M = 0x001C0000;
		public static final int ALIGNMENT_512M = 0x001D0000;
		public static final int ALIGNMENT_1G = 0x001E0000;
		public static final int ALIGNMENT_2G = 0x001F0000;
	}

	public static final UUID EFI_SYSTEM_NV_DATA_FV_GUID =
			UUID.fromString("FFF12B8D-7696-4C8B-A985-2747075B4F50");
}
