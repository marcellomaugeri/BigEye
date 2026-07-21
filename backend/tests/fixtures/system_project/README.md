# BigEye system campaign fixture

This original fixture accepts at most 4096 bytes from standard input or from
`--file PATH`. It has two explicit runtime configurations:

- `--mode plain` sends the bytes directly to the target parser.
- `--mode framed` requires the input to begin with `FRAME:` and parses the
  remaining bytes.

`BIGEYE_DEFAULT_FRAMED=ON` changes the build-time default without removing the
runtime override. Both normal campaign configurations expose the same healthy
`A...` payload. Deterministic mutations to `B...` and `C...` take distinct
instrumented paths before reaching the same deliberate copy-boundary defect.
The expected inputs under `crashes/` are test evidence only and are removed
before the browser acceptance repository is committed and served.
