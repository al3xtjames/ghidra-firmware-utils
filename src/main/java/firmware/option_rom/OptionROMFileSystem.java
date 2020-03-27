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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "pcir", description = "PCI Option ROM", factory = OptionROMFileSystemFactory.class)
public class OptionROMFileSystem implements GFileSystem {
	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<OptionROMHeader> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private ByteProvider provider;

	public OptionROMFileSystem(FSRLRoot fsFSRL) {
		this.fsFSRL = fsFSRL;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	public void mount(ByteProvider provider, TaskMonitor monitor) throws IOException {
		this.provider = provider;
		int imageOffset = 0;
		while (true) {
			// Read each subsequent image and add it to the map (until the last image is read).
			ByteProviderWrapper imageProvider =
					new ByteProviderWrapper(provider, imageOffset, provider.length() - imageOffset);
			BinaryReader reader = new BinaryReader(imageProvider, true);
			OptionROMHeader header = OptionROMHeaderFactory.parseOptionROM(reader);
			PCIDataStructureHeader pcirHeader = header.getPCIRHeader();
			imageOffset += pcirHeader.getImageLength();

			String filename = String.format("Image %d: %s", fsih.getFileCount() + 1,
				OptionROMConstants.CodeType.toString(pcirHeader.getCodeType()));
			fsih.storeFileWithParent(filename, null, -1, false, pcirHeader.getImageLength(),
				header);
			if (pcirHeader.isLastImage()) {
				break;
			}
		}
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
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
	public String getInfo(GFile file, TaskMonitor monitor) {
		OptionROMHeader entry = fsih.getMetadata(file);
		return (entry != null) ? entry.toString() : null;
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		return fsih.getListing(directory);
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
		OptionROMHeader entry = fsih.getMetadata(file);
		return entry.getImageStream();
	}
}
