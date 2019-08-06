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
//UEFI helper script

import firmware.common.UUIDUtils;
import firmware.uefi_te.TELoader;
import firmware.uefi_te.TerseExecutableHeader;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.MachineConstants;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeSubsystem;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.UUID;

/**
 * UEFI helper script
 */
public class UEFIHelper extends GhidraScript {
	private DataTypeManager uefiTypeManager;

	/**
	 * Loads the specified data type library and returns a corresponding DataTypeManager.
	 *
	 * @param name the name of the data type library
	 * @return     the DataTypeManager for the specified data type library
	 */
	private DataTypeManager loadDataTypeLibrary(String name) throws DuplicateIdException,
			IOException {
		// Check if the data type library was already loaded.
		DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);
		DataTypeManager[] managers = service.getDataTypeManagers();
		for (DataTypeManager manager : managers) {
			if (manager.getName().equals(name)) {
				return manager;
			}
		}

		// Load the data type library from the plugin's data directory.
		File dataTypeFile = new File(new File(
				sourceFile.getParentFile().getParentFile().getFile(true), "data"), name);
		return service.openArchive(dataTypeFile, false).getDataTypeManager();
	}

	/**
	 * Updates a specified Function with the signature from a specified FunctionDefinition.
	 *
	 * @param function   the specified Function
	 * @param definition the specified FunctionDefinition
	 */
	private void updateFunctionSignature(Function function,
			FunctionDefinition definition) throws DuplicateNameException, InvalidInputException {
		// Build the list of parameters.
		ArrayList<ParameterImpl> parameters = new ArrayList<>();
		ParameterDefinition[] parameterDefinitions = definition.getArguments();
		for (ParameterDefinition parameterDefinition : parameterDefinitions) {
			parameters.add(new ParameterImpl(parameterDefinition.getName(),
					parameterDefinition.getDataType(), currentProgram));
		}

		// Build the return type.
		ReturnParameterImpl returnType = new ReturnParameterImpl(definition.getReturnType(),
				currentProgram);

		// Update the function with the generated parameter list and return type.
		function.setName(definition.getName(), SourceType.DEFAULT);
		function.updateFunction(null, returnType, parameters,
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.DEFAULT);
	}

	/**
	 * Defines a specified DataType at a specified Address. Existing data definitions that would
	 * conflict with the new DataType will be removed.
	 *
	 * @param address  the specified Address
	 * @param dataType the specified DataType
	 * @param name     the name to use for the data type's label
	 */
	private void defineData(Address address, DataType dataType, String name) throws Exception {
		// Remove any existing data definitions that would overlap with this definition.
		for (int i = 0; i < dataType.getLength(); i++) {
			Data existingData = getDataAt(address.add(i));
			if (existingData != null) {
				removeData(existingData);
			}
		}

		// Apply the data type definition and create a label.
		createData(address, dataType);
		createLabel(address, name, true);
	}

	/**
	 * Defines the signature for the current program's entry point function.
	 *
	 * @param entryPointAddress the address of the entry point function
	 */
	private void defineEntryPoint(Address entryPointAddress) throws DuplicateNameException,
			InvalidInputException {
		Function entryPoint = getFunctionAt(entryPointAddress);
		if (entryPoint == null) {
			// Create the entry point function if it wasn't already defined.
			entryPoint = createFunction(entryPointAddress, "_ModuleEntryPoint");
		}

		println("Found entry point function at 0x" + entryPointAddress.toString().toUpperCase());

		// TODO: Pick correct entry point signature based off module type (PEI vs DXE, etc)
		FunctionDefinition entryPointDefinition = (FunctionDefinition) uefiTypeManager.getDataType(
				"/UefiApplicationEntryPoint.h/functions/_ModuleEntryPoint");
		updateFunctionSignature(entryPoint, entryPointDefinition);
	}

	/**
	 * Searches for known GUIDs in the current program's .data segment and applies the EFI_GUID
	 * type definition.
	 */
	private void defineGUIDs() throws Exception {
		println("Searching for GUIDs...");

		// Read the contents .data segment.
		MemoryBlock dataBlock = currentProgram.getMemory().getBlock(".data");
		byte[] blockBytes = new byte[(int) dataBlock.getSize()];
		dataBlock.getBytes(dataBlock.getStart(), blockBytes);
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(blockBytes), true);

		// Find the EFI_GUID data type.
		DataType efiGuidType = uefiTypeManager.getDataType("/UefiBaseType.h/EFI_GUID");

		// Search for known GUIDs in the GUID database.
		Address firstGuidAddress = null;
		Address lastGuidAddress = null;
		long index = 0;
		while (index < dataBlock.getSize() - efiGuidType.getLength()) {
			UUID uuid = UUIDUtils.fromBinaryReader(reader);
			if (uuid.equals(UUID.fromString("00000000-0000-0000-0000-000000000000"))) {
				index += efiGuidType.getLength();
			} else {
				if (UUIDUtils.dbContains(uuid)) {
					lastGuidAddress = dataBlock.getStart().add(index);
					if (firstGuidAddress == null) {
						firstGuidAddress = lastGuidAddress;
					}

					println("GUID: Found " + UUIDUtils.getName(uuid) + " (" + uuid.toString() +
							") at 0x" + lastGuidAddress.toString().toUpperCase());

					// Remove any existing data that would overlap with this definition.
					for (int i = 0; i < efiGuidType.getLength(); i++) {
						Data existingData = getDataAt(lastGuidAddress.add(i));
						if (existingData != null) {
							removeData(existingData);
						}
					}

					// Apply the EFI_GUID data type for the GUID we found.
					defineData(lastGuidAddress, efiGuidType, UUIDUtils.getName(uuid));
					index += efiGuidType.getLength();
				} else {
					index += 1;
				}
			}

			reader.setPointerIndex(index);
		}

		// There may be undefined GUIDs present in the undefined data between the GUIDs we just
		// defined. Apply the EFI_GUID type to this undefined data.
		if (false && firstGuidAddress != null) {
			int unknownGuidNumber = 1;
			for (Address address = firstGuidAddress;
				 address.getUnsignedOffset() < lastGuidAddress.getUnsignedOffset();
				 address = address.add(efiGuidType.getLength())) {
				// Skip known GUIDs that we previously defined.
				Data data = getDataAt(address);
				if (data != null && data.getDataType().isEquivalent(efiGuidType)) {
					continue;
				}

				reader.setPointerIndex(address.subtract(dataBlock.getStart()));
				UUID uuid = UUIDUtils.fromBinaryReader(reader);
				String guidName = "UnknownGuid" + unknownGuidNumber++;
				println("GUID: Found " + guidName + " (" + uuid.toString() + ") at 0x" +
						address.toString().toUpperCase());

				// Apply the EFI_GUID data type.
				defineData(address, efiGuidType, guidName);
			}
		}
	}

	@Override
	public void run() throws Exception {
		println("UEFIHelper - UEFI helper script");

		// Make sure the current program is a UEFI executable.
		short machine;
		int subsystem;
		Address entryPointAddress = currentProgram.getImageBase();
		if (currentProgram.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			// Parse the PE headers.
			MemoryBlock peBlock = currentProgram.getMemory().getBlock(PeLoader.HEADERS);
			byte[] blockBytes = new byte[(int) peBlock.getSize()];
			peBlock.getBytes(peBlock.getStart(), blockBytes);
			FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader(
					RethrowContinuesFactory.INSTANCE, new ByteArrayProvider(blockBytes), true);
			int ntHeaderOffset = reader.readInt(0x3C);
			NTHeader ntHeader = NTHeader.createNTHeader(reader, ntHeaderOffset,
					PortableExecutable.SectionLayout.FILE, false, false);
			println("Loaded Portable Executable");

			machine = ntHeader.getFileHeader().getMachine();
			subsystem = ntHeader.getOptionalHeader().getSubsystem();
			entryPointAddress = entryPointAddress.add(
					ntHeader.getOptionalHeader().getAddressOfEntryPoint());
		} else if (currentProgram.getExecutableFormat().equals(TELoader.TE_NAME)) {
			// Parse the TE header.
			MemoryBlock teBlock = currentProgram.getMemory().getBlock(TELoader.HEADERS);
			byte[] blockBytes = new byte[(int) teBlock.getSize()];
			teBlock.getBytes(teBlock.getStart(), blockBytes);
			BinaryReader reader = new BinaryReader(new ByteArrayProvider(blockBytes), true);
			TerseExecutableHeader teHeader = new TerseExecutableHeader(reader);
			println("Loaded Terse Executable");

			machine = teHeader.getMachineType();
			subsystem = teHeader.getSubsystem();
			entryPointAddress = entryPointAddress.add(teHeader.getEntryPointAddress());
		} else {
			Msg.showError(this, null, "UEFIHelper", "Current program is not a PE/TE binary (" +
					currentProgram.getExecutableFormat() + ')');
			return;
		}

		// TODO: When https://github.com/NationalSecurityAgency/ghidra/pull/501 is merged, switch
		// to checking for the existence of the UEFI property in the current program's options.
		if (subsystem < PeSubsystem.IMAGE_SUBSYSTEM_EFI_APPLICATION.ordinal() &&
			subsystem > PeSubsystem.IMAGE_SUBSYSTEM_EFI_ROM.ordinal()) {
			Msg.showError(this, null, "UEFIHelper",
					"Current program is not a UEFI binary (subsystem = " + subsystem + ')');
			return;
		}

		String libraryName;
		switch (machine) {
			case MachineConstants.IMAGE_FILE_MACHINE_AMD64:
				libraryName = "uefi_x64.gdt";
				break;
			case MachineConstants.IMAGE_FILE_MACHINE_ARM:
				libraryName = "uefi_arm.gdt";
				break;
			case MachineConstants.IMAGE_FILE_MACHINE_ARM64:
				libraryName = "uefi_aarch64.gdt";
				break;
			case MachineConstants.IMAGE_FILE_MACHINE_I386:
				libraryName = "uefi_ia32.gdt";
				break;
			default:
				Msg.showError(this, null, "UEFIHelper",
						"No data type library present for current program's machine type (" +
						machine + ')');
				return;
		}

		// Load the UEFI data type library.
		uefiTypeManager = loadDataTypeLibrary(libraryName);

		// Fix the entry point function signature.
		defineEntryPoint(entryPointAddress);

		// Search for known GUIDs in the program's .data segment.
		defineGUIDs();
	}
}
