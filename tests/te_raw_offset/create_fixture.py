"""Create a synthetic TE image whose section RVA differs from its raw offset.

SPDX-License-Identifier: Apache-2.0
"""

import pathlib
import struct
import sys

header = struct.pack("<2sHBBHIIQIIII", b"VZ", 0x8664, 1, 10, 0x120,
                     0x1000, 0x1000, 0x100000, 0, 0, 0, 0)
section = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", 4, 0x1000, 4, 0x200,
                      0, 0, 0, 0, 0x60000020)
raw_offset = 0x200 - (0x120 - len(header))
image = header + section
image += bytes(raw_offset - len(image)) + bytes.fromhex("909090c3")
pathlib.Path(sys.argv[1]).write_bytes(image)
