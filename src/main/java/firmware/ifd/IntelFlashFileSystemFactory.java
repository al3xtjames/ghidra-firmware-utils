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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class IntelFlashFileSystemFactory implements GFileSystemFactoryByteProvider<IntelFlashFileSystem>,
		GFileSystemProbeByteProvider {
	@Override
	public boolean probe(ByteProvider provider, FileSystemService fsService, TaskMonitor monitor) throws IOException {
		return findIFDSignatureOffset(provider) != -1;
	}

	@Override
	public IntelFlashFileSystem create(FSRLRoot fsrlRoot, ByteProvider provider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException {
		IntelFlashFileSystem fs = new IntelFlashFileSystem(fsrlRoot);
		try {
			long offset = findIFDSignatureOffset(provider);
			if (offset < 0) {
				throw new IOException("IFD signature not found");
			}

			fs.mount(provider, offset, monitor);
			return fs;
		} catch (IOException ioe) {
			fs.close();
			throw ioe;
		}
	}

	private long findIFDSignatureOffset(ByteProvider provider) throws IOException {
		long offset = 0;
		long remainingLength = provider.length();
		BinaryReader reader = new BinaryReader(provider, true);
		while (remainingLength >= 4) {
			int signature = reader.readInt(offset);
			if (signature == IntelFlashDescriptorConstants.IFD_SIGNATURE) {
				if (remainingLength <= IntelFlashDescriptorConstants.DESCRIPTOR_SIZE - 16) {
					// Ignore binaries which lack regions other than the flash descriptor.
					return -1;
				}

				Msg.debug(this, String.format("Found IFD signature at 0x%X", offset));
				return offset;
			}

			offset += 4;
			remainingLength -= 4;
		}

		return -1;
	}
}
