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

package firmware.fmap;

import java.util.Formatter;

/**
 * Various Flash Map (FMAP) constants.
 */
public final class FlashMapConstants {
	// Flash Map signature
	public static final String FMAP_SIGNATURE = "__FMAP__";

	// Flash Map name length (including null terminator)
	public static final int FMAP_NAME_LEN = 32;

	// Flash area flags
	public static final class FlashAreaFlags {
		public static final byte STATIC = 1 << 0;
		public static final byte COMPRESSED = 1 << 1;
		public static final byte READ_ONLY = 1 << 2;
		public static final byte PRESERVE = 1 << 3;

		public static final String toString(short flags) {
			Formatter formatter = new Formatter();
			if (flags == 0) {
				formatter.format("None ");
			} else if ((flags & STATIC) != 0) {
				formatter.format("Static ");
			} else if ((flags & COMPRESSED) != 0) {
				formatter.format("Compressed ");
			} else if ((flags & READ_ONLY) != 0) {
				formatter.format("Read-only ");
			} else if ((flags & PRESERVE) != 0) {
				formatter.format("Preserved ");
			}

			return formatter.toString();
		}
	}
}
