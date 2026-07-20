# BigEye system campaign fixture

This original fixture accepts at most 4096 bytes from standard input or from
`--file PATH`. It has two explicit runtime configurations:

- `--mode plain` sends the bytes directly to the target parser.
- `--mode framed` requires the input to begin with `FRAME:` and parses the
  remaining bytes.

`BIGEYE_DEFAULT_FRAMED=ON` changes the build-time default without removing the
runtime override. The two files under `crashes/` differ but reach the same
deliberate copy-boundary defect. Normal campaign seeds live under `seeds/` and
do not crash at startup.
