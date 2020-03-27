package firmware.fmap;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FlashMapFileSystemFactory implements GFileSystemFactoryFull<FlashMapFileSystem>, GFileSystemProbeFull {

	@Override
	public FlashMapFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider provider, File containerFile,
			FileSystemService fsService, TaskMonitor monitor) throws IOException, CancelledException {

		FlashMapFileSystem fs = new FlashMapFileSystem(targetFSRL);
		try {
			long offset = findFMapSignatureOffset(provider);
			if (offset < 0) {
				throw new IOException("FMAP signature not found");
			}
			fs.mount(provider, offset, monitor);
			return fs;
		} catch (IOException ioe) {
			fs.close();
			throw ioe;
		}
	}

	@Override
	public boolean probe(FSRL containerFSRL, ByteProvider provider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		return findFMapSignatureOffset(provider) != -1;
	}

	private long findFMapSignatureOffset(ByteProvider provider) throws IOException {
		long remainingLength = provider.length();
		long offset = 0;
		while (remainingLength >= FlashMapConstants.FMAP_SIGNATURE.length()) {
			String signature = new String(provider.readBytes(offset, FlashMapConstants.FMAP_SIGNATURE.length()),
					StandardCharsets.US_ASCII);
			if (signature.equals(FlashMapConstants.FMAP_SIGNATURE)) {
				Msg.debug(this, String.format("Found FMAP signature at 0x%X", offset));
				return offset;
			}

			offset += FlashMapConstants.FMAP_SIGNATURE.length();
			remainingLength -= FlashMapConstants.FMAP_SIGNATURE.length();
		}

		return -1;

	}

}
