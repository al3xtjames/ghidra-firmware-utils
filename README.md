Ghidra Firmware Utilities
=========================

Various modules for [Ghidra][1] to assist with PC firmware reverse-engineering.
This was accepted as a [coreboot project][2] for GSoC 2019.

## Features (very much WIP)
### PCI option ROM loader
 - Implements a FS loader for PCI option ROMs (handles hybrid ROMs,
   e.g. legacy x86 + UEFI)
 - Loads uncompressed UEFI executables from PCI option ROMs
 - Calculates entry point address for legacy x86 option ROMs (still needs to be
   manually loaded as a raw real-mode binary)
 - TODO: Write loader for legacy x86 option ROMs (automatically select
   real-mode x86)
 - TODO: Implement support for compressed UEFI executables

## Planned functionality / TODO
### Firmware image loader
 - Implement FS loader for firmware images
 - Write parsers for Intel IFD (BIOS region), coreboot CBFS/FMAP, and UEFI
   firmware volumes

### UEFI loader
 - Write helper script to import GUIDs/etc (similar to [ida-efitools][3])

## Building & Installation

Ghidra's standard Gradle build system is used. Set the `GHIDRA_INSTALL_DIR`
environment variable before building:

```bash
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
gradle
```

The module ZIP will be output to `dist/`. Use **File > Install Extensions** and
select the green plus to browse to the extension. Restart Ghidra when prompted.

## Usage

### PCI option ROM loader
Add a PCI option ROM to a Ghidra project. When prompted to select an import
mode, select **File system**. The images contained within the option ROM will
be displayed, and can be imported for analysis. Information for each image can
be displayed by selecting **Get Info** in the right-click menu for an image.

[1]: https://ghidra-sre.org/
[2]: https://summerofcode.withgoogle.com/projects/#6413737605464064
[3]: https://github.com/danse-macabre/ida-efitools
