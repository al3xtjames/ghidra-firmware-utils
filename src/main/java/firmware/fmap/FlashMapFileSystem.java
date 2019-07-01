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

package firmware.fmap;

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

@FileSystemInfo(type = "fmap", description = "Flash Map", factory = GFileSystemBaseFactory.class)
public class FlashMapFileSystem extends GFileSystemBase {
	private long offset;
	private HashMap<GFile, FlashMapArea> map;

	public FlashMapFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
		offset = 0;
		map = new HashMap<>();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		long remainingLength = provider.length();
		while (remainingLength >= FlashMapConstants.FMAP_SIGNATURE.length()) {
			String signature = new String(provider.readBytes(offset,
					FlashMapConstants.FMAP_SIGNATURE.length()));
			if (signature.equals(FlashMapConstants.FMAP_SIGNATURE)) {
				Msg.debug(this, String.format("Found FMAP signature at 0x%X", offset));
				return true;
			}

			offset += FlashMapConstants.FMAP_SIGNATURE.length();
			remainingLength -= FlashMapConstants.FMAP_SIGNATURE.length();
		}

		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(offset);
		FlashMapHeader header = new FlashMapHeader(reader);
		FlashMapArea[] areas = header.getAreas();
		for (FlashMapArea area : areas) {
			GFileImpl file = GFileImpl.fromPathString(this, root, area.getName(), null, false,
					area.length());
			map.put(file, area);
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
		map.clear();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor) {
		FlashMapArea area = map.get(file);
		return area.getData();
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		FlashMapArea area = map.get(file);
		return area.toString();
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
