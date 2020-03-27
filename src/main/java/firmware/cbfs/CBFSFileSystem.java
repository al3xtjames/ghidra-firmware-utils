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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "cbfs", description = "Coreboot File System", factory = CBFSFileSystemFactory.class)
public class CBFSFileSystem implements GFileSystem {
	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<CBFSFile> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private ByteProvider provider;

	public CBFSFileSystem(FSRLRoot fsFSRL) {
		this.fsFSRL = fsFSRL;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	public void mount(ByteProvider provider, TaskMonitor monitor) throws IOException, CancelledException {
		this.provider = provider;
		BinaryReader reader = new BinaryReader(provider, false);

		// The first CBFS file should contain the CBFS master header.
		CBFSHeader header = new CBFSHeader(reader);
		Msg.debug(this, String.format("%s alignment = 0x%X", header.getName(), header.getAlignment()));
		reader.align(header.getAlignment());

		monitor.initialize(reader.length());
		monitor.setMessage("Mounting CBFS");
		// Read each CBFS file.
		while (reader.length() - reader.getPointerIndex() > 0) {
			monitor.checkCanceled();
			monitor.setProgress(reader.getPointerIndex());

			CBFSFile cbfsFile = new CBFSFile(reader);
			reader.align(header.getAlignment());
			String name = cbfsFile.getName().length() > 0 ? cbfsFile.getName().replace('/', '_') : "(empty)";
			Msg.debug(this, String.format("%s size = 0x%X, data offset = 0x%X, type = %s", name, cbfsFile.length(),
				cbfsFile.getOffset(), CBFSConstants.FileType.toString(cbfsFile.getType())));

			// Ignore empty CBFS files (used for padding).
			if (cbfsFile.getType() == CBFSConstants.FileType.NULL) {
				continue;
			}

			fsih.storeFileWithParent(name, null, -1, false, cbfsFile.length(), cbfsFile);
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
		CBFSFile cbfsFile = fsih.getMetadata(file);
		return (cbfsFile != null) ? cbfsFile.toString() : null;
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
		CBFSFile cbfsFile = fsih.getMetadata(file);
		return cbfsFile.getData();
	}
}
