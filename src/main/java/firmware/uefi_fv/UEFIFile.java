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

import ghidra.formats.gfilesystem.fileinfo.FileAttributes;

/**
 * Interface for UEFI firmware volume contents, such as UEFIFirmwareVolumes, UEIFFFSFiles, and
 * FFSSections.
 */
public interface UEFIFile {
	/**
	 * Returns the name of the current file.
	 *
	 * @return the name of the current file
	 */
	String getName();

	/**
	 * Returns the length of the current file.
	 *
	 * @return the length of the current file
	 */
	long length();

	/**
	 * Returns FileAttributes for the current image.
	 *
	 * @return FileAttributes for the current image
	 */
	FileAttributes getFileAttributes();
}
