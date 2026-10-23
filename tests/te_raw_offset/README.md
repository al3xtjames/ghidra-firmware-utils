# TE section raw-offset regression

The fixture is generated from scratch and contains no device/vendor firmware.
Its `.text` section has RVA `0x1000`, raw pointer `0x200`, and four bytes
`90 90 90 c3`. The stripped header size is `0x120`, so its raw content begins
at TE file offset `0x108`, while its loaded address is `0x101000`.

After building/installing the extension in a disposable Ghidra installation,
run from the repository root with `GHIDRA_INSTALL_DIR` pointing to it:

```sh
python3 tests/te_raw_offset/create_fixture.py /tmp/synthetic.te
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp te-regression -import /tmp/synthetic.te \
  -loader TELoader -noanalysis \
  -scriptPath "$PWD/tests/te_raw_offset" -postScript VerifyTESection.java \
  -deleteProject
```

On Windows, use `support/analyzeHeadless.bat` and equivalent absolute paths.
The post-script must print `TE_RAW_OFFSET_PASS`. A successful process
exit alone is insufficient because headless import/script errors can be logged
without propagating an exit failure.
