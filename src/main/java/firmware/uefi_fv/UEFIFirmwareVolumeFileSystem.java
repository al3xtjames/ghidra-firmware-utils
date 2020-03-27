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

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "fv", description = "UEFI Firmware Volume", factory = UEFIFirmwareVolumeFileSystemFactory.class)
public class UEFIFirmwareVolumeFileSystem implements GFileSystem {
	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<UEFIFile> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private ByteProvider provider;

	public UEFIFirmwareVolumeFileSystem(FSRLRoot fsFSRL) {
		this.fsFSRL = fsFSRL;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	public void mount(ByteProvider provider, TaskMonitor monitor)
			throws IOException, CancelledException {
		this.provider = provider;
		monitor.initialize(provider.length());
		monitor.setMessage("Mounting UEFI Firmware Volume");

		BinaryReader reader = new BinaryReader(provider, true);
		long headerIndex = UEFIFirmwareVolumeHeader.findNext(provider, 0, monitor);
		while (headerIndex != -1) {
			// Add each firmware volume as a directory.
			reader.setPointerIndex(headerIndex);
			UEFIFirmwareVolumeHeader header =
					new UEFIFirmwareVolumeHeader(reader, fsih, fsih.getRootDir(), false);
			headerIndex =
					UEFIFirmwareVolumeHeader.findNext(provider, headerIndex + header.length(), monitor);
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
		UEFIFile fvFile = fsih.getMetadata(file);
		return (fvFile != null) ? fvFile.toString() : null;
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
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		UEFIFile fvFile = fsih.getMetadata(file);
		if (fvFile instanceof FFSSection) {
			return ((FFSSection) fvFile).getData();
		}
		else if (fvFile instanceof FFSRawFile) {
			return ((FFSRawFile) fvFile).getData();
		}

		return null;
	}

	public static String getFSFormattedName(UEFIFile file, GFile parent,
			FileSystemIndexHelper<UEFIFile> fsih) {
		int fileCount = fsih.getListing(parent).size();
		String typeStr = (file instanceof UEFIFirmwareVolumeHeader) ? "Volume" : "File";
		return String.format("%s %03d - %s", typeStr, fileCount, file.getName());
	}

}
