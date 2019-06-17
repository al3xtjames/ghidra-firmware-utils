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

package firmware.cbfs;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

import java.io.IOException;

/**
 * Factory for constructing the correct CBFS file attribute based off the attribute tag field.
 */
public class CBFSFileAttributeFactory {
	private CBFSFileAttributeFactory() {}

	/**
	 * Constructs a CBFSFileAttribute from a specified BinaryReader by checking the attribute tag
	 * field.
	 *
	 * @param reader the specified BinaryReader
	 * @return       the parsed CBFSFileAttribute
	 */
	public static CBFSFileAttribute parseCBFSFileAttribute(BinaryReader reader) throws IOException {
		int tag = reader.peekNextInt();
		Msg.debug(CBFSFileAttribute.class, String.format("Found attribute with tag 0x%X", tag));

		switch (tag) {
			case CBFSConstants.AttributeTag.COMPRESSION:
				return new CBFSCompressionAttribute(reader);
			default:
				return new CBFSFileAttribute(reader);
		}
	}
}
