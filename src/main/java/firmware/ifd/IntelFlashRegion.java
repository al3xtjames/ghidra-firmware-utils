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

package firmware.ifd;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.BoundedInputStream;

import java.io.IOException;
import java.util.Formatter;

/**
 * Parser for Intel flash regions (using region information defined in a flash descriptor).
 */
public class IntelFlashRegion {
	private int baseAddress;
	private int length;
	private int type;
	private BoundedInputStream inputStream;

	/**
	 * Constructs an IntelFlashRegion from a specified BinaryReader.
	 *
	 * @param reader the specified BinaryReader
	 * @param length the length of the flash region in bytes
	 * @param type   the region type (see IntelFlashDescriptorConstants.FlashRegionType)
	 * @throws IOException
	 */
	public IntelFlashRegion(BinaryReader reader, int length, int type) throws IOException {
		baseAddress = (int) reader.getPointerIndex();
		this.length = length;
		this.type = type;
		inputStream = new BoundedInputStream(reader.getByteProvider().getInputStream(baseAddress),
				length);
	}

	/**
	 * Returns a BoundedInputStream for the contents of the current flash region.
	 *
	 * @return a BoundedInputStream for the contents of the current flash region
	 */
	public BoundedInputStream getDataStream() {
		return inputStream;
	}

	/**
	 * Returns the current flash region's type.
	 *
	 * @return the current flash region's type
	 */
	public int getType() {
		return type;
	}

	/**
	 * Returns the length of the current flash region.
	 *
	 * @return the length of the current flash region
	 */
	public int length() {
		return length;
	}

	@Override
	public String toString() {
		Formatter formatter = new Formatter();
		formatter.format("Region name: %s (type %d)\n",
				IntelFlashDescriptorConstants.FlashRegionType.toString(type), type);
		formatter.format("Region base address: 0x%X\n", baseAddress);
		formatter.format("Region size: 0x%X", length);
		return formatter.toString();
	}
}
