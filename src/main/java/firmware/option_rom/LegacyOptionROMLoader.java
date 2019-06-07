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

package firmware.option_rom;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class LegacyOptionROMLoader extends AbstractLibrarySupportLoader {
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		ArrayList<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		LegacyOptionROMHeader header = null;
		try {
			header = new LegacyOptionROMHeader(reader);
		} catch (IOException e) {
			return loadSpecs;
		}

		loadSpecs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair("x86:LE:16:Real Mode", "default"), true));
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor,
			MessageLog log) throws IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		LegacyOptionROMHeader header = new LegacyOptionROMHeader(reader);

		// Create a segment for the entire option ROM.
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		InputStream romStream = provider.getInputStream(0);
		try {
			api.createMemoryBlock("Option ROM", api.toAddr(0), romStream, romStream.available(),
					false);
		} catch (Exception e) {
			Msg.showError(this, null, getName() + " Loader", e.getMessage(), e);
			return;
		}

		// Retrieve the decoded entry point address from the legacy option ROM header, and define
		// the entry point function.
		Address entryPoint = api.toAddr(header.getEntryPointOffset());
		api.addEntryPoint(entryPoint);
		api.createFunction(entryPoint, "entry");

		// Mark the legacy option ROM header, PCI data structure, and device list as data.
		try {
			api.createData(api.toAddr(0), header.toDataType());
			PCIDataStructureHeader pcirHeader = header.getPCIRHeader();
			api.createData(api.toAddr(header.getPCIRHeaderOffset()), pcirHeader.toDataType());

			DeviceList deviceList = header.getDeviceList();
			if (deviceList != null) {
				api.createData(api.toAddr(header.getPCIRHeaderOffset() +
						pcirHeader.getDeviceListOffset()), deviceList.toDataType());
			}
		} catch (Exception e) {
			Msg.showError(this, null, getName() + " Loader", e.getMessage(), e);
		}
	}

	@Override
	public String getName() {
		return "x86 PCI Option ROM";
	}
}
