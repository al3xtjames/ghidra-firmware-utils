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
 * Various UEFI Firmware File System (FFS) constants.
 */
public final class UEFIFFSConstants {
	// Size of the UEFI FFS header structure
	public static final int FFS_HEADER_SIZE = 24;

	// UEFI FFS attributes
	public static final class Attributes {
		public static final byte LARGE_FILE = 0x01;
		public static final byte FIXED = 0x04;
		public static final byte DATA_ALIGNMENT = 0x38;
		public static final byte CHECKSUM = 0x40;
	}

	// UEFI FFS file types
	public static final class FileType {
		public static final byte ALL = 0x00;
		public static final byte RAW = 0x01;
		public static final byte FREEFORM = 0x02;
		public static final byte SECURITY_CORE = 0x03;
		public static final byte PEI_CORE = 0x04;
		public static final byte DXE_CORE = 0x05;
		public static final byte PEIM = 0x06;
		public static final byte DRIVER = 0x07;
		public static final byte COMBINED_PEIM_DRIVER = 0x08;
		public static final byte APPLICATION = 0x09;
		public static final byte SMM = 0x0A;
		public static final byte FIRMWARE_VOLUME_IMAGE = 0x0B;
		public static final byte COMBINED_SMM_DXE = 0x0C;
		public static final byte SMM_CORE = 0x0D;
		public static final byte OEM_MIN = (byte) 0xC0;
		public static final byte OEM_MAX = (byte) 0xDF;
		public static final byte DEBUG_MIN = (byte) 0xE0;
		public static final byte DEBUG_MAX = (byte) 0xEF;
		public static final byte PAD = (byte) 0xF0;

		public static String toString(byte type) {
			switch (type) {
				case ALL:
					return "All";
				case RAW:
					return "Raw";
				case FREEFORM:
					return "Freeform";
				case SECURITY_CORE:
					return "SEC Core";
				case PEI_CORE:
					return "PEI Core";
				case DXE_CORE:
					return "DXE Core";
				case PEIM:
					return "PEI Module";
				case DRIVER:
					return "DXE Driver";
				case COMBINED_PEIM_DRIVER:
					return "Combined PEI Module/Driver";
				case APPLICATION:
					return "Application";
				case SMM:
					return "SMM Module";
				case FIRMWARE_VOLUME_IMAGE:
					return "Firmware Volume Image";
				case COMBINED_SMM_DXE:
					return "Combined SMM Module/DXE Driver";
				case SMM_CORE:
					return "SMM Core";
				default:
					return "Unknown File Type";
			}
		}
	}

	// Size of the common UEFI FFS section header structure
	public static final int FFS_SECTION_HEADER_SIZE = 4;

	// UEFI FFS section types
	public static final class SectionType {
		public static final byte COMPRESSION = 0x01;
		public static final byte GUID_DEFINED = 0x02;
		public static final byte DISPOSABLE = 0x03;
		public static final byte PE32 = 0x10;
		public static final byte PIC = 0x11;
		public static final byte TE = 0x12;
		public static final byte DXE_DEPEX = 0x13;
		public static final byte VERSION = 0x14;
		public static final byte USER_INTERFACE = 0x15;
		public static final byte COMPATIBILITY16 = 0x16;
		public static final byte FIRMWARE_VOLUME_IMAGE = 0x17;
		public static final byte FREEFORM_SUBTYPE_GUID = 0x18;
		public static final byte RAW = 0x19;
		public static final byte PEI_DEPEX = 0x1B;
		public static final byte SMM_DEPEX = 0x1C;

		public static String toString(byte type) {
			switch (type) {
				case COMPRESSION:
					return "Compressed Section";
				case GUID_DEFINED:
					return "GUID-Defined Section";
				case DISPOSABLE:
					return "Disposable Section";
				case PE32:
				case PIC:
					return "PE32 Image Section";
				case TE:
					return "TE Image Section";
				case DXE_DEPEX:
					return "DXE Dependency Section";
				case VERSION:
					return "Version Section";
				case USER_INTERFACE:
					return "UI Section";
				case COMPATIBILITY16:
					return "Compatibility16 (CSM)";
				case FIRMWARE_VOLUME_IMAGE:
					return "Firmware Volume Image Section";
				case FREEFORM_SUBTYPE_GUID:
					return "Freeform Subtype GUID Section";
				case RAW:
					return "Raw Section";
				case PEI_DEPEX:
					return "PEI Dependency Section";
				case SMM_DEPEX:
					return "SMM Dependency Section";
				default:
					return "Unknown Section Type";
			}
		}
	}

	// UEFI FFS GUID-defined section attributes
	public static final class DefinedSectionAttributes {
		public static final short PROCESSING_REQUIRED = 0x01;
		public static final short AUTH_STATUS_VALID = 0x02;
	}

	// UEFI FFS compression section compression types
	public static final class CompressionType {
		public static final byte NOT_COMPRESSED = 0x00;
		public static final byte STANDARD_COMPRESSION = 0x01;
		public static final byte CUSTOMIZED_COMPRESSION = 0x02;

		public static String toString(byte type) {
			switch (type) {
				case NOT_COMPRESSED:
					return "Uncompressed";
				case STANDARD_COMPRESSION:
					return "Standard (EFI 1.1/Tiano)";
				case CUSTOMIZED_COMPRESSION:
					return "Customized (LZMA)";
				default:
					return "Unknown";
			}
		}
	}

	// Tiano compression GUID (for GUID-defined sections)
	public static final UUID TIANO_COMPRESS_GUID =
			UUID.fromString("A31280AD-481E-41B6-95E8-127F4C984779");

	// LZMA compression GUID (for GUID-defined sections)
	public static final UUID LZMA_COMPRESS_GUID =
			UUID.fromString("EE4E5898-3914-4259-9D6E-DC7BD79403CF");

	// CRC-32 GUID (for GUID-defined sections)
	public static final UUID CRC32_GUID =
			UUID.fromString("FC1BCDB0-7D31-49AA-936A-A4600D9DD083");
}
