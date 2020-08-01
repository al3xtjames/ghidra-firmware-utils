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

package firmware.uefi_te;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pe.MachineConstants;
import ghidra.app.util.bin.format.pe.PeSubsystem;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Loader for Terse Executable (TE) binaries. Terse Executables are simplified PE/COFF executables,
 * used in the UEFI PI stage.
 */
public class TELoader extends AbstractLibrarySupportLoader {
	public static final String HEADERS = "Headers";
	public static final String TE_NAME = "Terse Executable (TE)";

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		ArrayList<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		TerseExecutableHeader header = null;
		try {
			header = new TerseExecutableHeader(reader);
		} catch (IOException e) {
			return loadSpecs;
		}

		switch (header.getMachineType()) {
			case MachineConstants.IMAGE_FILE_MACHINE_I386:
				loadSpecs.add(new LoadSpec(this, header.getImageBase(),
						new LanguageCompilerSpecPair("x86:LE:32:default", "windows"), true));
				break;
			case MachineConstants.IMAGE_FILE_MACHINE_AMD64:
				loadSpecs.add(new LoadSpec(this, header.getImageBase(),
						new LanguageCompilerSpecPair("x86:LE:64:default", "windows"), true));
				break;
			case MachineConstants.IMAGE_FILE_MACHINE_ARM64:
				loadSpecs.add(new LoadSpec(this, header.getImageBase(),
						new LanguageCompilerSpecPair("AARCH64:LE:64:v8A", "windows"), true));
				break;
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
						Program program, TaskMonitor monitor,
						MessageLog log) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		TerseExecutableHeader teHeader = new TerseExecutableHeader(reader);
		EFIImageSectionHeader[] sectionHeaders = teHeader.getSections();
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		InputStream inputStream = provider.getInputStream(0);

		try {
			// Create a segment for the TE header and section headers.
			api.createMemoryBlock(HEADERS, api.toAddr(
					teHeader.getImageBase() + teHeader.getHeaderOffset()), inputStream,
					TerseExecutableConstants.TE_HEADER_SIZE + teHeader.getNumSections() *
					TerseExecutableConstants.SECTION_HEADER_SIZE, false);

			// Mark the TE header and section headers as data.
			api.createData(api.toAddr(teHeader.getImageBase() + teHeader.getHeaderOffset()),
					teHeader.toDataType());
			long sectionHeaderOffset = teHeader.getImageBase() + teHeader.getHeaderOffset() +
					TerseExecutableConstants.TE_HEADER_SIZE;
			for (EFIImageSectionHeader sectionHeader : sectionHeaders) {
				api.createData(api.toAddr(sectionHeaderOffset), sectionHeader.toDataType());
				sectionHeaderOffset += TerseExecutableConstants.SECTION_HEADER_SIZE;
			}

			// Create a segment for each section.
			for (EFIImageSectionHeader sectionHeader : sectionHeaders) {
				// Skip empty sections.
				if (sectionHeader.getVirtualSize() == 0) {
					Msg.debug(this, "Skipping empty section: " + sectionHeader.getName());
					continue;
				}

				inputStream = provider.getInputStream(sectionHeader.getVirtualAddress() -
						teHeader.getHeaderOffset());
				long startAddress = teHeader.getImageBase() + sectionHeader.getVirtualAddress();
				try {
					MemoryBlock section = api.createMemoryBlock(sectionHeader.getName(),
							api.toAddr(startAddress), inputStream, sectionHeader.getVirtualSize(),
							false);

					// Set the appropriate permissions for this segment.
					section.setRead(sectionHeader.isReadable());
					section.setWrite(sectionHeader.isWritable());
					section.setExecute(sectionHeader.isExecutable());

					Msg.debug(this, String.format("Added %s section: 0x%X-0x%X",
							sectionHeader.getName(), startAddress, startAddress +
							sectionHeader.getVirtualSize()));
				} catch (AddressOverflowException e) {
					Msg.showWarn(this, null, getName() + " Loader",
							"Skipping overflowing section " + sectionHeader.getName() + ": " +
							e.getMessage(), e);
				} catch (AddressOutOfBoundsException e) {
					// This is thrown immediately after AddressOverflowException. Ignore this since
					// we should have already shown the warning message.
				}
			}

			// Set the UEFI property if this a UEFI binary.
			if (teHeader.getSubsystem() >= PeSubsystem.IMAGE_SUBSYSTEM_EFI_APPLICATION.ordinal() &&
				teHeader.getSubsystem() <= PeSubsystem.IMAGE_SUBSYSTEM_EFI_ROM.ordinal()) {
				program.getOptions(Program.PROGRAM_INFO).setBoolean("UEFI", true);
			}

			// Define the entry point function.
			Address entryPoint = api.toAddr(teHeader.getImageBase() + teHeader.getEntryPointAddress());
			api.addEntryPoint(entryPoint);
			api.createFunction(entryPoint, "_ModuleEntryPoint");
		} catch (Exception e) {
			Msg.showError(this, null, getName() + " Loader", e.getMessage(), e);
		}
	}

	@Override
	public String getName() {
		return TE_NAME;
	}
}
