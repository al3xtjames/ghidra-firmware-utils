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

import ghidra.app.util.bin.BinaryReader;
import ghidra.formats.gfilesystem.GFile;

import java.io.IOException;

/**
 * Factory for constructing the correct FFSSection based off the type field in the common FFS
 * section header.
 */
public class FFSSectionFactory {
	private FFSSectionFactory() {}

	/**
	 * Constructs a FFSSection from a specified BinaryReader by checking the type field in the
	 * common FFS section header. This should only be used for checking if a FFS section is a UI
	 * section.
	 *
	 * @param reader the specified BinaryReader
	 * @return       the parsed FFSSection
	 */
	public static FFSSection parseSection(BinaryReader reader) throws IOException {
		byte type = reader.readByte(reader.getPointerIndex() + 3);
		switch (type) {
			case UEFIFFSConstants.SectionType.USER_INTERFACE:
				return new FFSUISection(reader);
			default:
				return new FFSGenericSection(reader);
		}
	}

	/**
	 * Constructs a FFSSection from a specified BinaryReader by checking the type field in the
	 * common FFS section header, and adds it to the specified UEFIFirmwareVolumeFileSystem.
	 *
	 * @param reader the specified BinaryReader
	 * @param fs     the specified UEFIFirmwareVolumeFileSystem
	 * @param parent the parent directory in the specified UEFIFirmwareVolumeFileSystem
	 * @return       the parsed FFSSection
	 */
	public static FFSSection parseSection(BinaryReader reader,
			UEFIFirmwareVolumeFileSystem fs, GFile parent) throws IOException {
		byte type = reader.readByte(reader.getPointerIndex() + 3);
		switch (type) {
			case UEFIFFSConstants.SectionType.COMPRESSION:
				return new FFSCompressedSection(reader, fs, parent);
			case UEFIFFSConstants.SectionType.GUID_DEFINED:
				return new FFSGUIDDefinedSection(reader, fs, parent);
			case UEFIFFSConstants.SectionType.VERSION:
				return new FFSVersionSection(reader, fs, parent);
			case UEFIFFSConstants.SectionType.USER_INTERFACE:
				return new FFSUISection(reader, fs, parent);
			case UEFIFFSConstants.SectionType.FIRMWARE_VOLUME_IMAGE:
				return new FFSVolumeImageSection(reader, fs, parent);
			case UEFIFFSConstants.SectionType.FREEFORM_SUBTYPE_GUID:
				return new FFSFreeformSubtypeSection(reader, fs, parent);
			default:
				return new FFSGenericSection(reader, fs, parent);
		}
	}
}
