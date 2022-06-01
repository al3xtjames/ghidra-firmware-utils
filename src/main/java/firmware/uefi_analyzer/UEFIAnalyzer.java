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

package firmware.uefi_analyzer;

import firmware.common.UUIDUtils;
import firmware.uefi_te.TELoader;
import firmware.uefi_te.TerseExecutableHeader;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.*;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.UUID;

public class UEFIAnalyzer extends AbstractAnalyzer {
	// To properly use an enum as an option, it must be public. Otherwise, only the default option (specified in the
	// call to registerOption) will show up in the drop down menu.
	public enum UEFIModuleType {
		DXE_MODULE("DXE Module"),
		PEI_MODULE("PEI Module");

		private final String optionDisplayString;

		UEFIModuleType(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	private UEFIModuleType moduleType;
	private DataTypeManager uefiTypeManager;

	// Options
	private static final String MODULE_TYPE_OPTION_NAME = "Module type";
	private static final UEFIModuleType MODULE_TYPE_DEFAULT_VALUE = UEFIModuleType.DXE_MODULE;

	public UEFIAnalyzer() {
		super("UEFI Analyzer", "Applies UEFI function/data type definitions.", AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check for the UEFI property (set by the TE loader).
		// When https://github.com/NationalSecurityAgency/ghidra/pull/501 is merged, this should also work with the PE
		// loader.
		if (program.getOptions(Program.PROGRAM_INFO).getBoolean("UEFI", false)) {
			return true;
		}

		// Parse the PE binary and check the subsystem to determine if this is a UEFI executable (fallback for current
		// Ghidra, where the UEFI property isn't set by the PE loader).
		if (program.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			try {
				NTHeader ntHeader = parseNTHeader(program);
				int subsystem = ntHeader.getOptionalHeader().getSubsystem();
				return (subsystem >= PeSubsystem.IMAGE_SUBSYSTEM_EFI_APPLICATION.ordinal() &&
						subsystem <= PeSubsystem.IMAGE_SUBSYSTEM_EFI_ROM.ordinal());
			}
			catch (Exception e) {
				Msg.error(this, "Failed to parse PE binary: " + e.getMessage());
			}
		}

		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(MODULE_TYPE_OPTION_NAME, MODULE_TYPE_DEFAULT_VALUE, null,
				"Used to determine the signature of the entry point function.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		moduleType = options.getEnum(MODULE_TYPE_OPTION_NAME, MODULE_TYPE_DEFAULT_VALUE);
	}

	@Override
	public boolean added(Program program, AddressSetView addressSetView, TaskMonitor taskMonitor,
						 MessageLog messageLog) throws CancelledException {
		Address entryPointAddress = program.getImageBase();

		// Parse the current PE/TE binary.
		short machine;
		int subsystem;
		if (program.getExecutableFormat().equals(PeLoader.PE_NAME)) {
			try {
				NTHeader ntHeader = parseNTHeader(program);
				machine = ntHeader.getFileHeader().getMachine();
				subsystem = ntHeader.getOptionalHeader().getSubsystem();
				entryPointAddress = entryPointAddress.add(ntHeader.getOptionalHeader().getAddressOfEntryPoint());
			}
			catch (Exception e) {
				Msg.error(this, "Failed to parse PE binary: " + e.getMessage());
				return false;
			}
		}
		else if (program.getExecutableFormat().equals(TELoader.TE_NAME)) {
			try {
				TerseExecutableHeader teHeader = parseTEHeader(program);
				machine = teHeader.getMachineType();
				subsystem = teHeader.getSubsystem();
				entryPointAddress = entryPointAddress.add(teHeader.getEntryPointAddress());
			}
			catch (Exception e) {
				Msg.error(this, "Failed to parse TE binary: " + e.getMessage());
				return false;
			}
		}
		else {
			// This shouldn't be possible (canAnalyze should have returned false), but check anyways.
			Msg.error(this, "Current program is not a PE/TE binary");
			return false;
		}

		// This shouldn't be possible (canAnalyze should have returned false), but check anyways.
		if (subsystem < PeSubsystem.IMAGE_SUBSYSTEM_EFI_APPLICATION.ordinal() ||
				subsystem > PeSubsystem.IMAGE_SUBSYSTEM_EFI_ROM.ordinal()) {
			Msg.error(this, String.format("Current program is not a UEFI binary (subsystem = %d)", subsystem));
			return false;
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
				Msg.error(this, "No data type library present for machine type: " + machine);
				return false;
		}

		// Load the UEFI data type library.
		PluginTool tool = AutoAnalysisManager.getAnalysisManager(program).getAnalysisTool();
		try {
			uefiTypeManager = loadDataTypeLibrary(tool, libraryName);
		}
		catch (Exception e) {
			Msg.error(this, "Failed to load UEFI data type library (" + libraryName +  "): " + e.getMessage());
			return false;
		}

		// Create the entry point function (if it doesn't already exist) and update its signature.
		Function entryPoint;
		try {
			entryPoint = getEntryPointFunction(program, addressSetView, entryPointAddress);
			updateEntryPointFunctionSignature(program, entryPoint, moduleType);
		}
		catch (Exception e) {
			Msg.error(this, "Failed to update entry point function: " + e.getMessage());
			return false;
		}

		// Search for known GUIDs in the .data and .text sections.
		String[] guidSections = {".data", ".text"};
		for (String section : guidSections) {
			MemoryBlock block = program.getMemory().getBlock(section);
			if (block != null) {
				try {
					defineGUIDs(program, block);
				}
				catch (Exception e) {
					Msg.error(this, "Failed to define GUIDs: " + e.getMessage());
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Parses the NT header in the specified Program.
	 *
	 * @param program the specified Program
	 */
	private static NTHeader parseNTHeader(Program program)
			throws InvalidNTHeaderException, IOException, MemoryAccessException {
		MemoryBlock peBlock = program.getMemory().getBlock(PeLoader.HEADERS);
		byte[] blockBytes = new byte[(int) peBlock.getSize()];
		peBlock.getBytes(peBlock.getStart(), blockBytes);
		FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader(
				RethrowContinuesFactory.INSTANCE, new ByteArrayProvider(blockBytes), true);
		int ntHeaderOffset = reader.readInt(0x3C);
		return NTHeader.createNTHeader(reader, ntHeaderOffset,
				PortableExecutable.SectionLayout.FILE, false, false);
	}

	/**
	 * Parses the TE header in the specified Program.
	 *
	 * @param program the specified Program
	 */
	private static TerseExecutableHeader parseTEHeader(Program program) throws IOException, MemoryAccessException {
		MemoryBlock teBlock = program.getMemory().getBlock(TELoader.HEADERS);
		byte[] blockBytes = new byte[(int) teBlock.getSize()];
		teBlock.getBytes(teBlock.getStart(), blockBytes);
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(blockBytes), true);
		return new TerseExecutableHeader(reader);
	}

	/**
	 * Loads the specified data type library and returns a corresponding DataTypeManager.
	 *
	 * @param tool the specified PluginTool
	 * @param name the name of the data type library
	 * @return     the DataTypeManager for the specified data type library
	 */
	private DataTypeManager loadDataTypeLibrary(PluginTool tool, String name)
			throws DuplicateIdException, IOException {
		// Check if the data type library was already loaded.
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] managers = service.getDataTypeManagers();
		for (DataTypeManager manager : managers) {
			if (manager.getName().equals(name)) {
				return manager;
			}
		}

		// Load the data type library from the extension's data directory.
		return service.openArchive(Application.getModuleDataFile(name).getFile(true), false).getDataTypeManager();
	}

	/**
	 * Updates a specified Function in a specified Program with the signature from a specified FunctionDefinition.
	 *
	 * @param program    the specified Program
	 * @param function   the specified Function
	 * @param definition the specified FunctionDefinition
	 */
	private static void updateFunctionSignature(Program program, Function function,
			FunctionDefinition definition) throws DuplicateNameException, InvalidInputException {
		// Build the list of parameters.
		ArrayList<ParameterImpl> parameters = new ArrayList<>();
		ParameterDefinition[] parameterDefinitions = definition.getArguments();
		for (ParameterDefinition parameterDefinition : parameterDefinitions) {
			parameters.add(new ParameterImpl(
					parameterDefinition.getName(), parameterDefinition.getDataType(), program));
		}

		// Build the return type.
		ReturnParameterImpl returnType = new ReturnParameterImpl(definition.getReturnType(), program);

		// Update the function with the generated parameter list and return type.
		function.setName(definition.getName(), SourceType.ANALYSIS);
		function.updateFunction(null, returnType, parameters, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false,
				SourceType.ANALYSIS);
	}

	/**
	 * Returns the entry point Function for the specified Program at the specified Address. It will be created if it
	 * doesn't already exist.
	 *
	 * @param program           the specified Program
	 * @param addressSetView    the AddressSetView for the specified Program
	 * @param entryPointAddress the Address of the entry point function
	 */
	private Function getEntryPointFunction(Program program, AddressSetView addressSetView, Address entryPointAddress)
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException  {
		Function entryPoint = program.getFunctionManager().getFunctionAt(entryPointAddress);
		if (entryPoint == null) {
			// Create the entry point function if it wasn't already defined.
			entryPoint = program.getFunctionManager().createFunction("_ModuleEntryPoint", entryPointAddress,
				addressSetView, SourceType.ANALYSIS);
		}
		else {
			entryPoint.setName("_ModuleEntryPoint", SourceType.ANALYSIS);
		}

		return entryPoint;
	}

	/**
	 * Updates the signature for the specified Program's entry point function.
	 *
	 * @param program    the specified Program
	 * @param entryPoint the entry point Function
	 * @param moduleType the UEFI module type
	 */
	private void updateEntryPointFunctionSignature(Program program, Function entryPoint, UEFIModuleType moduleType)
			throws DuplicateNameException, InvalidInputException {
		// Apply the correct entry point function definition based off the current module type.
		FunctionDefinition entryPointDefinition = null;
		switch (moduleType) {
			case DXE_MODULE:
				entryPointDefinition = (FunctionDefinition) uefiTypeManager.getDataType(
						"/UefiApplicationEntryPoint.h/functions/_ModuleEntryPoint");
				break;
			case PEI_MODULE:
				entryPointDefinition = (FunctionDefinition) uefiTypeManager.getDataType(
						"/PeimEntryPoint.h/functions/_ModuleEntryPoint");
				break;
		}

		updateFunctionSignature(program, entryPoint, entryPointDefinition);
	}

	/**
	 * Defines a specified DataType at a specified Address in the specified Program. Existing data or instructions that
	 * would conflict with the new DataType will be removed.
	 *
	 * @param program  the specified Program
	 * @param address  the specified Address
	 * @param dataType the specified DataType
	 * @param name     an optional name to use for the data type's label
	 * @param comment  an optional comment
	 */
	private static void defineData(Program program, Address address, DataType dataType, String name,
			String comment) throws Exception {
		FlatProgramAPI flatProgram = new FlatProgramAPI(program);
		// Remove any existing data or instructions that would overlap with this definition.
		for (int i = 0; i < dataType.getLength(); i++) {
			Address currentAddress = address.add(i);
			Data existingData = program.getListing().getDataAt(currentAddress);
			if (existingData != null) {
				flatProgram.removeData(existingData);
			}
			else {
				Instruction existingInstruction = flatProgram.getInstructionAt(currentAddress);
				if (existingInstruction != null) {
					flatProgram.removeInstruction(existingInstruction);
				}
			}
		}

		// Apply the data type definition and create a label (if specified).
		flatProgram.createData(address, dataType);
		if (name != null) {
			flatProgram.createLabel(address, name, true);
		}

		// Add a comment (if specified).
		if (comment != null) {
			flatProgram.setPlateComment(address, comment);
		}
	}

	/**
	 * Searches for known GUIDs in the specified MemoryBlock (in the specified program) and applies the EFI_GUID data
	 * type.
	 *
	 * @param program the specified Program
	 * @param block   the specified MemoryBlock
	 */
	private void defineGUIDs(Program program, MemoryBlock block) throws Exception {
		// Read the contents .data segment.
		byte[] blockBytes = new byte[(int) block.getSize()];
		block.getBytes(block.getStart(), blockBytes);
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(blockBytes), true);

		// Find the EFI_GUID data type.
		DataType efiGuidType = uefiTypeManager.getDataType("/UefiBaseType.h/EFI_GUID");

		// Search for known GUIDs in the GUID database.
		long index = 0;
		while (index < block.getSize() - efiGuidType.getLength()) {
			UUID guid = UUIDUtils.fromBinaryReader(reader);
			if (UUIDUtils.dbContains(guid)) {
				Address guidAddress = block.getStart().add(index);
				Msg.debug(this, String.format(
						"Found %s (%s) at 0x%s", UUIDUtils.getName(guid), guid.toString(),
						guidAddress.toString().toUpperCase()));

				// Apply the EFI_GUID data type for the GUID we found.
				defineData(program, guidAddress, efiGuidType, UUIDUtils.getName(guid), guid.toString());
				index += efiGuidType.getLength();
			}
			else {
				index += 1;
			}

			reader.setPointerIndex(index);
		}
	}
}
