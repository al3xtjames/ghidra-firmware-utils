package firmware.uefi_fv;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class UEFIFirmwareVolumeFileSystemFactory
implements GFileSystemFactoryFull<UEFIFirmwareVolumeFileSystem>, GFileSystemProbeFull {

	@Override
	public boolean probe(FSRL containerFSRL, ByteProvider provider, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
					throws IOException, CancelledException {
		long headerIndex = UEFIFirmwareVolumeHeader.findNext(provider, 0, monitor);
		return headerIndex != -1;
	}

	@Override
	public UEFIFirmwareVolumeFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
			ByteProvider provider, File containerFile, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {

		UEFIFirmwareVolumeFileSystem fs = new UEFIFirmwareVolumeFileSystem(targetFSRL);
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
