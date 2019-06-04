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

package util;

import ghidra.framework.Application;
import ghidra.framework.Platform;

import java.io.File;
import java.io.FileNotFoundException;

public abstract class JNILibraryLoader {
	public static void loadLibrary(String name) throws FileNotFoundException, UnsatisfiedLinkError {
		File libraryPath = Application.getOSFile(System.mapLibraryName(name));
		System.load(libraryPath.getAbsolutePath());
	}
}
