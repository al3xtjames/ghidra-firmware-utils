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

package firmware.ifd;

/**
 * Various Intel Flash Descriptor constants.
 */
public final class IntelFlashDescriptorConstants {
	// Intel Flash Descriptor signature (little endian)
	public static final int IFD_SIGNATURE = 0x0FF0A55A;
	public static final byte[] IFD_SIGNATURE_BYTES = {0x5A, (byte) 0xA5, (byte) 0xF0, 0x0F};

	// Flash region types
	public static final class FlashRegionType {
		public static final int FLASH_DESCRIPTOR = 0;
		public static final int BIOS = 1;
		public static final int MANAGEMENT_ENGINE = 2;
		public static final int GIGABIT_ETHERNET = 3;
		public static final int PLATFORM_DATA = 4;
		public static final int DEVICE_EXPANSION_1 = 5;
		public static final int SECONDARY_BIOS = 6;
		public static final int MICROCODE = 7;
		public static final int EMBEDDED_CONTROLLER = 8;
		public static final int DEVICE_EXPANSION_2 = 9;
		public static final int INNOVATION_ENGINE = 10;
		public static final int TEN_GIGABIT_ETHERNET_1 = 11;
		public static final int TEN_GIGABIT_ETHERNET_2 = 12;
		public static final int PLATFORM_TRUST_TECHNOLOGY = 15;

		public static String toString(int type) {
			switch (type) {
				case FLASH_DESCRIPTOR:
					return "Flash Descriptor";
				case BIOS:
					return "BIOS";
				case MANAGEMENT_ENGINE:
					return "Intel Management Engine";
				case GIGABIT_ETHERNET:
					return "Gigabit Ethernet";
				case PLATFORM_DATA:
					return "Platform Data";
				case DEVICE_EXPANSION_1:
					return "Device Expansion 1";
				case SECONDARY_BIOS:
					return "Secondary BIOS";
				case MICROCODE:
					return "CPU Microcode";
				case EMBEDDED_CONTROLLER:
					return "Embedded Controller";
				case DEVICE_EXPANSION_2:
					return "Device Expansion 2";
				case INNOVATION_ENGINE:
					return "Intel Innovation Engine";
				case TEN_GIGABIT_ETHERNET_1:
					return "10 Gigabit Ethernet 1";
				case TEN_GIGABIT_ETHERNET_2:
					return "10 Gigabit Ethernet 2";
				case PLATFORM_TRUST_TECHNOLOGY:
					return "Platform Trust Technology";
				default:
					return "Reserved";
			}
		}
	}

	// Size of the flash descriptor region
	public static final int DESCRIPTOR_SIZE = 4096;

	// Flash read frequencies
	// Used to determine IFD version
	public static final class FlashFrequency {
		public static final int FREQ_20_MHZ = 0;
		public static final int FREQ_50_MHZ_30_MHZ = 4;
		public static final int FREQ_17_MHz = 6;
	}
}
