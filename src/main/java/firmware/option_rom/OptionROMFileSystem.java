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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

@FileSystemInfo(type = "pcir", description = "PCI Option ROM", factory = GFileSystemBaseFactory.class)
public class OptionROMFileSystem extends GFileSystemBase {
	private HashMap<GFile, OptionROMHeader> map = new HashMap<>();

	public OptionROMFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] signature = provider.readBytes(0, 2);
		if (!Arrays.equals(signature, OptionROMConstants.ROM_SIGNATURE_BYTES)) {
			return false;
		}

		try {
			// Ignore option ROMs that contain a single legacy x86 image; those should be loaded
			// directly by LegacyOptionROMLoader.
			BinaryReader reader = new BinaryReader(provider, true);
			LegacyOptionROMHeader header = new LegacyOptionROMHeader(reader);
			// This is needed to avoid treating nested images (e.g. a legacy image in an open
			// hybrid expansion ROM filesystem) as an identical ROM filesystem.
			return header.getPCIRHeader().getImageLength() != provider.length();
		} catch (IOException e) {}

		return true;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {
		int imageOffset = 0;
		while (true) {
			// Read each subsequent image and add it to the map (until the last image is read).
			byte[] bytes = provider.readBytes(imageOffset, provider.length());
			BinaryReader reader = new BinaryReader(new ByteArrayProvider(bytes), true);
			OptionROMHeader header = OptionROMHeaderFactory.parseOptionROM(reader);
			PCIDataStructureHeader pcirHeader = header.getPCIRHeader();
			imageOffset += pcirHeader.getImageLength();

			String filename = String.format("Image %d: %s", map.size() + 1,
					OptionROMConstants.CodeType.toString(pcirHeader.getCodeType()));
			GFileImpl file = GFileImpl.fromPathString(this, root, filename, null, false,
					pcirHeader.getImageLength());

			map.put(file, header);
			if (pcirHeader.isLastImage()) {
				break;
			}
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
		map.clear();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor) throws IOException {
		OptionROMHeader entry = map.get(file);
		return entry.getImageStream();
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		OptionROMHeader entry = map.get(file);
		return entry.toString();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
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
}
