Ghidra Firmware Utilities
=========================

Various modules for [Ghidra][1] to assist with PC firmware reverse engineering.
This was accepted as a [coreboot project for GSoC 2019][2].

## Features
### PCI option ROM loader
 - Implements a FS loader for PCI option ROMs (handles hybrid ROMs with
   multiple images, e.g. legacy x86 + UEFI)
 - Loads UEFI executables from PCI option ROMs (including compressed images)
 - Defines the entry point function and various header data types for legacy
   x86 option ROMs

### Firmware image loader
 - Implements a FS loader for Flash Map (FMAP) images and Intel Flash
   Descriptor (IFD) images (shows flash regions)
 - Implements a FS loader for Coreboot Filesystem (CBFS) images (displays
   included files and handles compression)
 - Implements a FS loader for UEFI firmware volumes and nested firmware
   filesystem (FFS) file/FFS section parsing

### Terse Executable (TE) loader
 - Implements a binary loader for TE binaries (frequently used in UEFI PI)

### UEFI helper script
 - Includes data type libraries for base UEFI types (taken from EDK2 MdePkg)
 - Fixes the signature of the entry point function
 - Defines known GUIDs in the binary's .data/.text segments
 - Locates and defines global copies of UEFI table pointers (gBS/gRT/gST/etc)

## Building & Installation
Ghidra 9.1.0 (or newer) is required.

Ghidra's standard Gradle build system is used. Set the `GHIDRA_INSTALL_DIR`
environment variable before building, or set it as a Gradle property (useful
for building in an IDE):

### Environment variable
```bash
$ export GHIDRA_INSTALL_DIR="/path/to/ghidra"
$ ./gradlew
```

### Gradle property
```bash
echo GHIDRA_INSTALL_DIR=/path/to/ghidra > gradle.properties
```

The module ZIP will be output to `dist/`. Use **File > Install Extensions** and
select the green plus to browse to the extension. Restart Ghidra when prompted.

For proper functionality, the plugin should be built with the same JRE used
by your Ghidra installation. If you have multiple Java runtime environments
installed, select the correct JRE by setting the `JAVA_HOME` environment
variable before building.

## Usage
### PCI option ROM loader
Add a PCI option ROM to a Ghidra project. Legacy x86 option ROMs can be
directly loaded for analysis. Ensure that the binary format is set to
**x86 PCI Option ROM**, and import the binary.

UEFI option ROMs or option ROMs that contain more than one image should be
imported using the filesystem loader. When prompted to select an import mode,
select **File system**. The images contained within the option ROM will be
displayed, and can be imported for analysis. Legacy x86 images will be handled
the x86 PCI Option ROM loader, and UEFI images will be handled by the PE32
loader (compression is supported). Information for each image can be displayed
by selecting **Get Info** in the right-click menu.

### Firmware image loader
Add a supported firmware image to a Ghidra project. The firmware image loader
supports Intel images with a Flash Descriptor, coreboot images with a FMAP/CBFS
layout, and UEFI firmware volumes. The **File system** import mode can be used
to view embedded files within the specified firmware image.

Note that some UEFI firmware images may store nested firmware volumes within
freeform/raw files (or freeform/raw FFS sections). Such files can be imported
as firmware volumes by selecting **Open File System** in the right-click menu
for the specified freeform/raw file. If no nested firmware volume is found, an
error message will be displayed (`No file system provider for...`).

### UEFI helper script
The helper script is included in the plugin's ghidra_scripts directory, which
should be automatically added to the list of script directories in Ghidra.

Run the UEFI helper script by selecting UEFIHelper.java in the Script Manager
window (accessed from **Window -> Script Manager**).

To modify the UEFI data type library, modify the PRF template in
`data/gen_prf.sh` as necessary and generate new PRF files. Open the generated
PRF file in **File -> Parse C Source**. Build the updated data type library
by selecting **Parse to File...**. Overwrite the original data type libraries
in `data` and rebuild the plugin.

## License
Apache 2.0, with some exceptions:

 - `src/efidecompress/c/efidecompress.c`: BSD

## Credits
`src/efidecompress/c/efidecompress.c` is a lightly modified version of
[Decompress.c][4] from uefi-firmware-parser (which itself is derived from
[the original in EDK2 BaseTools][5]).

`lib/xz-1.8.jar` is taken from the [XZ for Java][6] project.

The IFD FS loader in `src/main/java/firmware/ifd` used the parser from
[UEFITool][7] as a reference.

The GUID database in `data/guids.csv` is taken from [UEFITool][8].

The UEFI data type libraries in `data/uefi_*.gdt` were generated with
`data/gen_prf.sh`, which is partially based off the UEFI parser definition
from [a Ghidra pull request by wrffrz][9]. These data type libraries use
headers from [EDK2 MdePkg][10].

[GhidraVitaLoader by xerpi][11] was used as a reference for some parts of the
UEFI helper script.

[1]: https://ghidra-sre.org/
[2]: https://summerofcode.withgoogle.com/projects/#6413737605464064
[3]: https://github.com/danse-macabre/ida-efitools
[4]: https://github.com/theopolis/uefi-firmware-parser/blob/21106baf019db9dcd046a3c01ee7b32212de45a5/uefi_firmware/compression/Tiano/Decompress.c
[5]: https://github.com/tianocore/edk2/blob/2e351cbe8e190271b3716284fc1076551d005472/BaseTools/Source/C/Common/Decompress.c
[6]: https://tukaani.org/xz/java.html
[7]: https://github.com/LongSoft/UEFITool
[8]: https://github.com/LongSoft/UEFITool/blob/f863caac9df1c5258e9bcc0441a695b6a3bbaf7c/common/guids.csv
[9]: https://github.com/NationalSecurityAgency/ghidra/pull/501#issuecomment-498374810
[10]: https://github.com/tianocore/edk2/tree/d21e5dbbbf11589113d39619b3e01eb1e8966819/MdePkg/Include
[11]: https://github.com/xerpi/GhidraVitaLoader
