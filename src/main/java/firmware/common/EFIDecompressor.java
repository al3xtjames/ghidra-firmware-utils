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

import ghidra.util.Msg;
import util.JNILibraryLoader;

/**
 * Handles the decompression of images compressed with the EFI Compression Algorithm.
 */
public class EFIDecompressor {
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

	private EFIDecompressor() {}

	/**
	 * Decompresses the specified compressed image. Implemented by the efidecompress native
	 * library.
	 *
	 * @param compressedImage the compressed image
	 */
	private static native byte[] nativeDecompress(byte[] compressedImage);

	/**
	 * Decompressed the specified compressed image.
	 *
	 * @param compressedImage the compressed image
	 */
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
