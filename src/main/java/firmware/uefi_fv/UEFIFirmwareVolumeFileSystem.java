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
import java.io.InvalidObjectException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "fv", description = "UEFI Firmware Volume", factory = UEFIFirmwareVolumeFileSystemFactory.class)
public class UEFIFirmwareVolumeFileSystem implements GFileSystem {
	private final FSRLRoot fsFSRL;
	private final FileSystemIndexHelper<UEFIFile> fsih;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
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
	public GFile lookup(String path) throws IOException {
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
		UEFIFile fvFile = fsih.getMetadata(file);
		ByteProvider provider;
		if (fvFile instanceof FFSSection) {
			provider = ((FFSSection) fvFile).getByteProvider();
		}
		else if (fvFile instanceof FFSRawFile) {
			provider = ((FFSRawFile) fvFile).getByteProvider();
		}
		else {
			throw new InvalidObjectException("Not a valid FFS file");
		}

		return new ByteProviderWrapper(provider, file.getFSRL());
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		UEFIFile fvFile = fsih.getMetadata(file);
		return fvFile.getFileAttributes();
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

	public static String getFSFormattedName(UEFIFile file, GFile parent,
			FileSystemIndexHelper<UEFIFile> fsih) {
		int fileCount = fsih.getListing(parent).size();
		String typeStr = (file instanceof UEFIFirmwareVolumeHeader) ? "Volume" : "File";
		return String.format("%s %03d - %s", typeStr, fileCount, file.getName());
	}
}
