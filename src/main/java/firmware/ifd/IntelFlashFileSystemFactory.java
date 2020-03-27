package firmware.ifd;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class IntelFlashFileSystemFactory implements GFileSystemFactoryFull<IntelFlashFileSystem>, GFileSystemProbeFull {

	@Override
	public boolean probe(FSRL containerFSRL, ByteProvider provider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		return findIFDSignatureOffset(provider) != -1;
	}

	@Override
	public IntelFlashFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider provider,
			File containerFile, FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		IntelFlashFileSystem fs = new IntelFlashFileSystem(targetFSRL);
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
