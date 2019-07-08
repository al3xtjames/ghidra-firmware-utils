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

package firmware.common;

import ghidra.app.util.bin.BinaryReader;
import ghidra.framework.Application;
import ghidra.util.Msg;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.UUID;

/**
 * Various UUID utilities.
 */
public class UUIDUtils {
	private static HashMap<UUID, String> guidMap = new HashMap<>();

	static {
		try {
			// Read the list of GUIDs to populate the GUID database.
			File guidDbFile = Application.getModuleDataFile("guids.csv").getFile(true);
			BufferedReader reader = new BufferedReader(new FileReader(guidDbFile));
			for (String line; (line = reader.readLine()) != null; ) {
				String[] parsedLine = line.split(",");
				guidMap.put(UUID.fromString(parsedLine[0]), parsedLine[1]);
			}

			Msg.debug(UUIDUtils.class, "Imported " + guidMap.size() + " GUIDs");
		} catch (IOException e) {
			Msg.error(UUIDUtils.class, "Failed to import GUID database");
		}
	}

	private UUIDUtils() {}

	/**
	 * Constructs a UUID from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 * @return       the constructed UUID
	 */
	public static UUID fromBinaryReader(BinaryReader reader) throws IOException {
		boolean wasReaderLittleEndian = reader.isLittleEndian();

		reader.setLittleEndian(true);
		long guidData1 = reader.readNextUnsignedInt() << 32;
		long guidData2 = (reader.readNextUnsignedShort() << 16) & 0xFFFFFFFFL;
		long guidData3 = reader.readNextUnsignedShort();
		long uuidMsb = guidData1 | guidData2 | guidData3;

		reader.setLittleEndian(false);
		long uuidLsb = reader.readNextLong();

		reader.setLittleEndian(wasReaderLittleEndian);
		return new UUID(uuidMsb, uuidLsb);
	}

	/**
	 * Retrieves the name for a specified UUID. If no name is found, a string representation of the
	 * UUID is returned.
	 *
	 * @return the name for the specified UUID
	 */
	public static String getName(UUID uuid) {
		if (guidMap == null || !guidMap.containsKey(uuid)) {
			return uuid.toString();
		}

		return guidMap.get(uuid);
	}
}
