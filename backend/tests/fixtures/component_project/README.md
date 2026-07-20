# BigEye component campaign fixture

The parser consumes a one-byte record kind, a one-byte declared payload length,
and that many payload bytes. The public contract requires a non-null output
record. `harnesses/correct.c` follows that contract. The deliberately incorrect
harness passes a null output pointer so BigEye can prove that a reproducible
crash disappears when only the harness is corrected.
