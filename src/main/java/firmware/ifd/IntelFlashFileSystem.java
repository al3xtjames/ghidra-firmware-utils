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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

@FileSystemInfo(type = "ifd", description = "Intel Flash Descriptor", factory = GFileSystemBaseFactory.class)
public class IntelFlashFileSystem extends GFileSystemBase {
	private long offset;
	private HashMap<GFile, IntelFlashRegion> map;

	public IntelFlashFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
		offset = 0;
		map = new HashMap<>();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		long remainingLength = provider.length();
		while (remainingLength >= 4) {
			byte[] signature = provider.readBytes(offset, 4);
			if (Arrays.equals(signature, IntelFlashDescriptorConstants.IFD_SIGNATURE_BYTES)) {
				Msg.debug(this, String.format("Found IFD signature at 0x%X", offset));
				if (remainingLength <= IntelFlashDescriptorConstants.DESCRIPTOR_SIZE - 16) {
					// Ignore binaries which lack regions other than the flash descriptor.
					return false;
				}

				return true;
			}

			offset += 4;
			remainingLength -= 4;
		}

		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(offset - 16);
		IntelFlashDescriptor ifd = new IntelFlashDescriptor(reader);
		ArrayList<IntelFlashRegion> regions = ifd.getRegions();
		for (IntelFlashRegion region : regions) {
			String regionName = String.format("Region %02d - %s", region.getType(),
					IntelFlashDescriptorConstants.FlashRegionType.toString(region.getType()));
			GFileImpl file = GFileImpl.fromPathString(this, root, regionName, null, false,
					region.length());
			map.put(file, region);
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
		map.clear();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor) {
		IntelFlashRegion entry = map.get(file);
		return entry.getDataStream();
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		IntelFlashRegion entry = map.get(file);
		return entry.toString();
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
}
