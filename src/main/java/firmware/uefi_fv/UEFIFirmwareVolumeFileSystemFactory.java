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

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class UEFIFirmwareVolumeFileSystemFactory implements
		GFileSystemFactoryByteProvider<UEFIFirmwareVolumeFileSystem>, GFileSystemProbeByteProvider {

	@Override
	public boolean probe(ByteProvider provider, FileSystemService fsService, TaskMonitor monitor)
					throws IOException, CancelledException {
		long headerIndex = UEFIFirmwareVolumeHeader.findNext(provider, 0, monitor);
		return headerIndex != -1;
	}

	@Override
	public UEFIFirmwareVolumeFileSystem create(FSRLRoot fsrlRoot, ByteProvider provider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		UEFIFirmwareVolumeFileSystem fs = new UEFIFirmwareVolumeFileSystem(fsrlRoot);
		try {
			fs.mount(provider, monitor);
			return fs;
		}
		catch (IOException ioe) {
			fs.close();
			throw ioe;
		}
	}
}
