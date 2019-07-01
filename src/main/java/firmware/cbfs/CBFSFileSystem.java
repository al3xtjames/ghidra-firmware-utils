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

@FileSystemInfo(type = "cbfs", description = "Coreboot File System", factory = GFileSystemBaseFactory.class)
public class CBFSFileSystem extends GFileSystemBase {
	private HashMap<GFile, CBFSFile> map;

	public CBFSFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
		map = new HashMap<>();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		String signature = new String(provider.readBytes(0,
				CBFSConstants.CBFS_FILE_SIGNATURE.length()));
		if (signature.equals(CBFSConstants.CBFS_FILE_SIGNATURE)) {
			return true;
		}

		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);
		// The first CBFS file should contain the CBFS master header.
		CBFSHeader header = new CBFSHeader(reader);
		Msg.debug(this, String.format("%s alignment = 0x%X", header.getName(),
				header.getAlignment()));
		reader.align(header.getAlignment());

		// Read each CBFS file.
		while (reader.length() - reader.getPointerIndex() > 0) {
			CBFSFile cbfsFile = new CBFSFile(reader);
			reader.align(header.getAlignment());
			String name = cbfsFile.getName().length() > 0 ? cbfsFile.getName().replace('/', '_') :
					"(empty)";
			Msg.debug(this, String.format("%s size = 0x%X, data offset = 0x%X, type = %s",
					name, cbfsFile.length(), cbfsFile.getOffset(),
					CBFSConstants.FileType.toString(cbfsFile.getType())));

			// Ignore empty CBFS files (used for padding).
			if (cbfsFile.getType() == CBFSConstants.FileType.NULL) {
				continue;
			}

			GFileImpl file = GFileImpl.fromPathString(this, root, name, null, false,
					cbfsFile.length());
			map.put(file, cbfsFile);
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
		map.clear();
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor) throws IOException {
		CBFSFile cbfsFile = map.get(file);
		return cbfsFile.getData();
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		CBFSFile cbfsFile = map.get(file);
		return cbfsFile.toString();
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
