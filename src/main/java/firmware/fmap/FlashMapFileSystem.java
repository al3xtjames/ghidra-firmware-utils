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

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "fmap", description = "Flash Map", factory = FlashMapFileSystemFactory.class)
public class FlashMapFileSystem implements GFileSystem {
	private final FSRLRoot fsFSRL;
	private final FileSystemIndexHelper<FlashMapArea> fsih;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
	private ByteProvider provider;

	public FlashMapFileSystem(FSRLRoot fsFSRL) {
		this.fsFSRL = fsFSRL;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	public void mount(ByteProvider provider, long offset, TaskMonitor monitor) throws IOException {
		this.provider = provider;
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(offset);
		FlashMapHeader header = new FlashMapHeader(reader);
		FlashMapArea[] areas = header.getAreas();
		for (FlashMapArea area : areas) {
			fsih.storeFileWithParent(area.getName(), null, -1, false, area.length(), area);
		}
	}

	@Override
	public GFile lookup(String path) {
		return fsih.lookup(path);
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}

		fsih.clear();
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		FlashMapArea area = fsih.getMetadata(file);
		return new ByteProviderWrapper(area.getByteProvider(), file.getFSRL());
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		FlashMapArea area = fsih.getMetadata(file);
		return area.getFileAttributes();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		return fsih.getListing(directory);
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}
}
