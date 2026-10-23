// SPDX-License-Identifier: Apache-2.0
// Verify the synthetic TE raw-offset regression after importing with TELoader.
// @category Firmware Tests

import java.util.Arrays;
import ghidra.app.script.GhidraScript;

public class VerifyTESection extends GhidraScript {
    @Override
    public void run() throws Exception {
        byte[] actual = new byte[4];
        int count = currentProgram.getMemory().getBytes(toAddr(0x101000), actual);
        byte[] expected = {(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0xc3};
        if (count != expected.length || !Arrays.equals(actual, expected)) {
            throw new Exception("TE section was not loaded from its raw data offset");
        }
        println("TE_RAW_OFFSET_PASS");
    }
}
