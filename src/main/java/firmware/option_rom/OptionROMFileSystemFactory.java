package firmware.option_rom;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OptionROMFileSystemFactory implements GFileSystemFactoryFull<OptionROMFileSystem>, GFileSystemProbeFull {

	@Override
	public boolean probe(FSRL containerFSRL, ByteProvider provider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		byte[] signature = provider.readBytes(0, 2);
		if (!Arrays.equals(signature, OptionROMConstants.ROM_SIGNATURE_BYTES)) {
			return false;
		}

		try {
			// Ignore option ROMs that contain a single legacy x86 image; those should be loaded
			// directly by LegacyOptionROMLoader.
			BinaryReader reader = new BinaryReader(provider, true);
			LegacyOptionROMHeader header = new LegacyOptionROMHeader(reader);
			// This is needed to avoid treating nested images (e.g. a legacy image in an open
			// hybrid expansion ROM filesystem) as an identical ROM filesystem.
			return header.getPCIRHeader().getImageLength() != provider.length();
		} catch (IOException e) {
		}

		return true;
	}

	@Override
	public OptionROMFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, ByteProvider provider,
			File containerFile, FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		OptionROMFileSystem fs = new OptionROMFileSystem(targetFSRL);
		try {
			fs.mount(provider, monitor);
			return fs;
		} catch (IOException ioe) {
			fs.close();
			throw ioe;
		}
	}

}
