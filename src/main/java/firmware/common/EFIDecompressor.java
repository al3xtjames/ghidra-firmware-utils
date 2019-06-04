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

import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.framework.main.AppInfo;
import ghidra.util.Msg;
import util.JNILibraryLoader;

public abstract class EFIDecompressor {
	private static boolean loadFailed = false;
	private static Throwable throwable = null;

	static {
		try {
			JNILibraryLoader.loadLibrary("efidecompress");
		} catch (Throwable t) {
			loadFailed = true;
			throwable = t;
		}
	}

	private static native byte[] nativeDecompress(byte[] compressedImage);

	public static byte[] decompress(byte[] compressedImage) {
		if (loadFailed) {
			Msg.showError(EFIDecompressor.class, null, "EFI Decompressor",
			              "Failed to load libefidecompress JNI library: " + throwable.getMessage(),
			              throwable);
			// FIXME: Find a proper way to stop the plugin and indicate that an error occurred
			return null;
		}

		return nativeDecompress(compressedImage);
	}
}
