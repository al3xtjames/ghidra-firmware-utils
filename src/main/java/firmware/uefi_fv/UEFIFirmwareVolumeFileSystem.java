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
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileImpl;
import ghidra.formats.gfilesystem.GFileSystemBase;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@FileSystemInfo(type = "fv", description = "UEFI Firmware Volume", factory = GFileSystemBaseFactory.class)
public class UEFIFirmwareVolumeFileSystem extends GFileSystemBase {
	private long headerIndex;
	private HashMap<GFile, UEFIFile> map;
	private HashMap<GFile, Integer> numberOfFiles;

	public UEFIFirmwareVolumeFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
		headerIndex = 0;
		map = new HashMap<>();
		numberOfFiles = new HashMap<>();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		return findNextFirmwareVolume();
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		do {
			// Add each firmware volume as a directory.
			reader.setPointerIndex(headerIndex);
			UEFIFirmwareVolumeHeader header = new UEFIFirmwareVolumeHeader(reader, this, root,
					false);
			headerIndex += header.length();
		} while (findNextFirmwareVolume());
	}

	@Override
	public void close() throws IOException {
		super.close();
		map.clear();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor) {
		UEFIFile fvFile = map.get(file);
		if (fvFile instanceof FFSSection) {
			return ((FFSSection) fvFile).getData();
		} else if (fvFile instanceof FFSRawFile) {
			return ((FFSRawFile) fvFile).getData();
		}

		return null;
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		UEFIFile fvFile = map.get(file);
		return fvFile.toString();
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		if (directory == null || directory.equals(root)) {
			ArrayList<GFile> roots = new ArrayList<>();
			for (GFile file : map.keySet()) {
				if (file.getParentFile() == root || file.getParentFile().equals(root)) {
					roots.add(file);
				}
			}

			return roots;
		}

		ArrayList<GFile> tmp = new ArrayList<>();
		for (GFile file : map.keySet()) {
			if (file.getParentFile() == null) {
				continue;
			}

			if (file.getParentFile().equals(directory)) {
				tmp.add(file);
			}
		}

		return tmp;
	}

	/**
	 * Adds a specified UEFIFile to the current filesystem with a specific name.
	 *
	 * @param parent      the parent file in the current filesystem
	 * @param file        the specified UEFIFile
	 * @param fileName    the name of the file
	 * @param isDirectory if the specified UEFIFile represents a directory
	 * @return            the constructed GFile implementation
	 */
	public GFile addFile(GFile parent, UEFIFile file, String fileName, boolean isDirectory) {
		// Add the specified file to the list of files.
		GFile fileImpl = GFileImpl.fromPathString(this, parent, fileName, null, isDirectory,
				file.length());
		map.put(fileImpl, file);

		return fileImpl;
	}

	/**
	 * Adds a specified UEFIFile to the current filesystem.
	 *
	 * @param parent      the parent file in the current filesystem
	 * @param file        the specified UEFIFile
	 * @param isDirectory if the specified UEFIFile represents a directory
	 * @return            the constructed GFile implementation
	 */
	public GFile addFile(GFile parent, UEFIFile file, boolean isDirectory) {
		// Generate a file name based off the file number.
		String fileName;
		int fileNum = numberOfFiles.getOrDefault(parent, 0);
		if (file instanceof UEFIFirmwareVolumeHeader) {
			fileName = String.format("Volume %03d - %s", fileNum++, file.getName());
		} else {
			fileName = String.format("File %03d - %s", fileNum++, file.getName());
		}

		// Update the number of child files for the parent directory.
		numberOfFiles.put(parent, fileNum);

		// Add the specified file to the list of files.
		return addFile(parent, file, fileName, isDirectory);
	}

	/**
	 * Finds the next firmware volume in the current firmware image.
	 *
	 * @return if an additional firmware volume was found
	 */
	private boolean findNextFirmwareVolume() throws IOException {
		long remainingLength = provider.length();
		while (remainingLength >= UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE.length()) {
			String signature = new String(provider.readBytes(headerIndex, 4));
			if (signature.equals(UEFIFirmwareVolumeConstants.UEFI_FV_SIGNATURE)) {
				if (remainingLength <= UEFIFirmwareVolumeConstants.UEFI_FV_HEADER_SIZE - 40) {
					return false;
				}

				if (headerIndex - 40 >= 0) {
					Msg.debug(this, String.format("Found _FVH signature at 0x%X", headerIndex));
					headerIndex -= 40;
					return true;
				}
			}

			headerIndex += 4;
			remainingLength -= 4;
		}

		return false;
	}
}
