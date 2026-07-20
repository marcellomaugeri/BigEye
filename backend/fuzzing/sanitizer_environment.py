"""Application-owned sanitizer settings for fuzzing runtime containers."""


BASELINE_SANITIZER_ENVIRONMENT = (
    ("ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0"),
    ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
)
