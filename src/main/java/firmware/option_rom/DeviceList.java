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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Formatter;

/**
 * Parser for the PCI expansion ROM device list. The device list is a zero-terminated list of
 * supported device IDs. The Device List Offset field in revision 3 of the PCI data structure is
 * used to calculate the device list's location.
 */
public class DeviceList implements StructConverter {
	private ArrayList<Short> deviceList;

	/**
	 * Constructs a DeviceList from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 */
	public DeviceList(BinaryReader reader) throws IOException {
		deviceList = new ArrayList<>();

		// The device ID list is zero-terminated.
		short lastDeviceID = reader.readNextShort();
		while (lastDeviceID != 0) {
			deviceList.add(lastDeviceID);
			lastDeviceID = reader.readNextShort();
		}
	}

	@Override
	public DataType toDataType() {
		Structure structure = new StructureDataType("device_list_t", 0);
		structure.add(new ArrayDataType(WORD, deviceList.size(), 2), "supported_device_ids", null);
		structure.add(WORD, 2, "terminator", null);
		return structure;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("Supported Device IDs: ");
		for (short deviceID : deviceList) {
			formatter.format("0x%02X ", deviceID);
		}

		return formatter.toString();
	}
}
