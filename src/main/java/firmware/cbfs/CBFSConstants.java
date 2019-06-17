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

package firmware.cbfs;

/*
 * Various coreboot File System (CBFS) constants.
 */
public final class CBFSConstants {
	// CBFS header signature
	public static final String CBFS_HEADER_SIGNATURE = "ORBC";

	// CBFS file signature
	public static final String CBFS_FILE_SIGNATURE = "LARCHIVE";

	// Minimum size of the CBFS file structure
	public static final int CBFS_FILE_SIZE = 24;

	// Minimum size of the CBFS file attributes structure
	public static final int CBFS_FILE_ATTRIBUTES_SIZE = 8;

	// CBFS file types
	public static final class FileType {
		public static final int BOOT_BLOCK = 0x01;
		public static final int CBFS_HEADER = 0x02;
		public static final int STAGE = 0x10;
		public static final int PAYLOAD = 0x20;
		public static final int FIT = 0x21;
		public static final int OPTION_ROM = 0x30;
		public static final int BOOT_SPLASH = 0x40;
		public static final int RAW = 0x50;
		public static final int VSA = 0x51;
		public static final int MBI = 0x52;
		public static final int MICROCODE = 0x53;
		public static final int FSP = 0x60;
		public static final int MRC = 0x61;
		public static final int MMA = 0x62;
		public static final int EFI = 0x63;
		public static final int STRUCT = 0x70;
		public static final int CMOS_DEFAULT = 0xAA;
		public static final int SPD = 0xAB;
		public static final int MRC_CACHE = 0xAC;
		public static final int CMOS_LAYOUT = 0x01AA;
		public static final int NULL = 0xFFFFFFFF;

		public static String toString(int type) {
			switch (type) {
				case BOOT_BLOCK:
					return "Boot Block";
				case CBFS_HEADER:
					return "CBFS Header";
				case STAGE:
					return "Stage";
				case PAYLOAD:
					return "Payload";
				case FIT:
					return "Firmware Interface Table";
				case OPTION_ROM:
					return "Option ROM";
				case BOOT_SPLASH:
					return "Boot Splash Image";
				case RAW:
					return "Raw";
				case VSA:
					return "VSA";
				case MBI:
					return "MBI";
				case MICROCODE:
					return "CPU Microcode";
				case FSP:
					return "Intel FSP";
				case MRC:
					return "Intel MRC";
				case MMA:
					return "MMA";
				case EFI:
					return "EFI";
				case STRUCT:
					return "Struct";
				case CMOS_DEFAULT:
					return "CMOS Defaults";
				case SPD:
					return "Memory SPD";
				case MRC_CACHE:
					return "MRC Cache";
				case CMOS_LAYOUT:
					return "CMOS Layout";
				case NULL:
					return "Null (Padding)";
				default:
					return "Unknown";
			}
		}
	}

	// CBFS file attribute tags
	public static final class AttributeTag {
		public static final int UNUSED = 0;
		public static final int UNUSED_2 = 0xFFFFFFFF;
		public static final int COMPRESSION = 0x42435A4C;
		public static final int HASH = 0x68736148;
		public static final int POSITION = 0x42435350;
		public static final int ALIGNMENT = 0x42434C41;
		public static final int PADDING = 0x47444150;
	}

	// CBFS compression algorithms
	public static final class CompressionAlgorithm {
		public static final int NONE = 0;
		public static final int LZMA = 1;
		public static final int LZ4 = 2;
	}
}
