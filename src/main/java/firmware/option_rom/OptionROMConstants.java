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

/**
 * Various PCI option ROM/PCI data structure constants.
 */
public final class OptionROMConstants {
	// PCI option ROM signature (little endian)
	public static final short ROM_SIGNATURE = (short) 0xAA55;
	public static final byte[] ROM_SIGNATURE_BYTES = {0x55, (byte) 0xAA};

	// PCI data structure header signature
	public static final String PCIR_SIGNATURE = "PCIR";

	// ROM size unit
	// The image length field in the PCI data structure header is in units of 512 bytes.
	public static final int ROM_SIZE_UNIT = 512;

	// PCI option ROM code type field
	public static final class CodeType {
		public static final byte PC_AT_COMPATIBLE = 0;
		public static final byte OPEN_FIRMWARE = 1;
		public static final byte PA_RISC = 2;
		public static final byte EFI = 3;

		public static String toString(byte codeType) {
			switch (codeType) {
				case PC_AT_COMPATIBLE:
					return "PC-AT Compatible";
				case OPEN_FIRMWARE:
					return "Open Firmware";
				case PA_RISC:
					return "PA-RISC";
				case EFI:
					return "EFI";
				default:
					return String.format("Unknown code type (0x%X)", codeType);
			}
		}
	}

	// (U)EFI option ROM signature (little endian)
	public static final int EFI_SIGNATURE = 0x00000EF1;

	// (U)EFI image subsystems (little endian)
	public static final class EFIImageSubsystem {
		public static final short APPLICATION = 10;
		public static final short BOOT_SERVICE_DRIVER = 11;
		public static final short RUNTIME_DRIVER = 12;

		public static String toString(short subsystem) {
			switch (subsystem) {
				case APPLICATION:
					return "EFI Application";
				case BOOT_SERVICE_DRIVER:
					return "EFI Boot Service Driver";
				case RUNTIME_DRIVER:
					return "EFI Runtime Driver";
				default:
					return String.format("Unknown EFI subsystem (0x%X)", subsystem);
			}
		}
	}

	// (U)EFI image machine types
	public static final class EFIImageMachineType {
		public static final short IA32 = 0x014C;
		public static final short IA64 = 0x0200;
		public static final short EBC = 0x0EBC;
		public static final short X64 = (short) 0x8664;
		public static final short ARMTHUMB_MIXED = 0x01C2;
		public static final short AARCH64 = (short) 0xAA64;
		public static final short RISCV32 = 0x5032;
		public static final short RISCV64 = 0x5064;
		public static final short RISCV128 = 0x5128;

		public static String toString(short machineType) {
			switch (machineType) {
				case IA32:
					return "x86";
				case IA64:
					return "IA64";
				case EBC:
					return "EFI Byte Code";
				case X64:
					return "x86_64";
				case ARMTHUMB_MIXED:
					return "ARM (mixed with Thumb)";
				case AARCH64:
					return "AArch64";
				case RISCV32:
					return "RISC-V (32-bit)";
				case RISCV64:
					return "RISC-V (64-bit)";
				case RISCV128:
					return "RISC-V (128-bit)";
				default:
					return String.format("Unknown EFI machine type (0x%X)", machineType);
			}
		}
	}
}
