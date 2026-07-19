"""Pure AFL++ and libFuzzer command and statistics contracts."""

from __future__ import annotations

import pytest


IMAGE_ID = "sha256:" + "c" * 64


def _spec(**changes):
    from backend.fuzzing.engines.contracts import EngineSpec

    values = {
        "engine": "afl",
        "image_id": IMAGE_ID,
        "target_command": ("/opt/bigeye/target", "--parse"),
        "input_mode": "file",
        "corpus_path": "/campaign/corpus",
        "output_path": "/campaign/output",
        "role": "main",
        "sanitizer_environment": {"ASAN_OPTIONS": "abort_on_error=1:symbolize=0"},
        "dictionary_path": None,
        "grammar_path": None,
        "timeout_ms": 1_500,
        "memory_limit_mb": 768,
        "campaign_labels": {"bigeye.configuration": "basic"},
    }
    values.update(changes)
    return EngineSpec(**values)


class TestAflCommand:
    def test_file_input_primary_command_is_exact_and_networkless(self) -> None:
        from backend.fuzzing.engines.afl.command import AflCommand

        invocation = AflCommand.build(_spec())

        assert invocation.command[:5] == [
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
        ]
        assert invocation.command[-1] == "@@"
        assert invocation.command[5:7] == ["-M", "main"]
        assert invocation.command[9:11] == ["-m", "0"]
        assert invocation.network_disabled is True
        assert invocation.read_only_source is True
        assert invocation.environment["ASAN_OPTIONS"] == "abort_on_error=1:symbolize=0"

    def test_secondary_stdin_dictionary_and_grammar_are_rendered_without_a_shell(self) -> None:
        from backend.fuzzing.engines.afl.command import AflCommand

        invocation = AflCommand.build(_spec(
            input_mode="stdin",
            role="worker-2",
            dictionary_path="/campaign/config/tokens.dict",
            grammar_path="/usr/local/lib/afl/libgrammarmutator-json.so",
        ))

        assert invocation.command[5:7] == ["-S", "worker-2"]
        assert invocation.command[-2:] == ["/opt/bigeye/target", "--parse"]
        assert "@@" not in invocation.command
        assert ["-x", "/campaign/config/tokens.dict"] == invocation.command[11:13]
        assert invocation.environment["AFL_CUSTOM_MUTATOR_LIBRARY"] == "/usr/local/lib/afl/libgrammarmutator-json.so"
        assert "AFL_CUSTOM_MUTATOR_ONLY" not in invocation.environment

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"engine": "libfuzzer"}, "engine must be afl"),
            ({"input_mode": "socket"}, "input_mode"),
            ({"corpus_path": "/tmp/corpus"}, "campaign path"),
            ({"target_command": ("sh", "-c", "target")}, "absolute"),
            ({"role": "bad role"}, "role"),
            ({"image_id": "sha256:not-a-digest"}, "immutable sha256"),
            ({"sanitizer_environment": {"ASAN_OPTIONS": "symbolize=0"}}, "abort_on_error=1"),
            ({"sanitizer_environment": {"ASAN_OPTIONS": "abort_on_error=1"}}, "symbolize=0"),
            ({"sanitizer_environment": {"ASAN_OPTIONS": "abort_on_error=1:abort_on_error=0:symbolize=0"}}, "abort_on_error=1"),
        ],
    )
    def test_rejects_invalid_contracts(self, change, message) -> None:
        from backend.fuzzing.engines.afl.command import AflCommand

        with pytest.raises(ValueError, match=message):
            AflCommand.build(_spec(**change))


class TestLibFuzzerCommand:
    def test_mounts_only_campaign_state_and_builds_exact_flags(self) -> None:
        from backend.fuzzing.engines.libfuzzer.command import LibFuzzerCommand

        invocation = LibFuzzerCommand.build(_spec(
            engine="libfuzzer",
            input_mode="inprocess",
            role="component-1",
            dictionary_path="/campaign/config/tokens.dict",
        ))

        assert invocation.command[:3] == [
            "/opt/bigeye/target", "--parse", "/campaign/corpus",
        ]
        assert "-artifact_prefix=/campaign/output/" in invocation.command
        assert "-timeout=2" in invocation.command
        assert "-rss_limit_mb=768" in invocation.command
        assert "-dict=/campaign/config/tokens.dict" in invocation.command
        assert invocation.read_only_source is True
        assert invocation.network_disabled is True

    def test_rejects_unsupported_grammar_and_wrong_engine(self) -> None:
        from backend.fuzzing.engines.libfuzzer.command import LibFuzzerCommand

        with pytest.raises(ValueError, match="grammar"):
            LibFuzzerCommand.build(_spec(engine="libfuzzer", input_mode="inprocess", grammar_path="/campaign/config/grammar.json"))
        with pytest.raises(ValueError, match="engine must be libfuzzer"):
            LibFuzzerCommand.build(_spec())


class TestEngineStatistics:
    def test_afl_parser_reports_observed_fields_without_strategy_decisions(self) -> None:
        from backend.fuzzing.engines.afl.stats import AflStats

        stats = AflStats.parse("""
fuzzer_pid        : 27
execs_done        : 1200
execs_per_sec     : 45.5
corpus_count      : 12
corpus_size       : 4096
last_find         : 1720000123
saved_crashes     : 2
saved_hangs       : 3
""")

        assert stats.execution_count == 1_200
        assert stats.execution_rate == 45.5
        assert stats.corpus_count == 12
        assert stats.corpus_size == 4_096
        assert stats.last_new_path == 1_720_000_123
        assert stats.crashes == 2
        assert stats.timeouts == 3
        assert stats.health == "active"

    def test_afl_parser_rejects_malformed_or_missing_required_values(self) -> None:
        from backend.fuzzing.engines.afl.stats import AflStats

        with pytest.raises(ValueError, match="execs_done"):
            AflStats.parse("execs_per_sec : 1\n")
        with pytest.raises(ValueError, match="execs_done"):
            AflStats.parse("execs_done : twelve\nexecs_per_sec : 1\n")

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
    def test_afl_parser_rejects_non_finite_rates(self, value: str) -> None:
        from backend.fuzzing.engines.afl.stats import AflStats

        with pytest.raises(ValueError, match="finite"):
            AflStats.parse(f"execs_done : 1\nexecs_per_sec : {value}\n")

    def test_libfuzzer_parser_uses_latest_progress_and_literal_failure_evidence(self) -> None:
        from backend.fuzzing.engines.libfuzzer.stats import LibFuzzerStats

        stats = LibFuzzerStats.parse("""
#10 INITED cov: 3 ft: 4 corp: 1/8b exec/s: 10 rss: 30Mb
#25 NEW    cov: 8 ft: 9 corp: 3/120b lim: 4 exec/s: 25 rss: 31Mb
#40 pulse  cov: 8 ft: 9 corp: 3/120b lim: 4 exec/s: 20 rss: 31Mb
Test unit written to /campaign/output/crash-abcd
SUMMARY: AddressSanitizer: heap-buffer-overflow
""")

        assert stats.execution_count == 40
        assert stats.execution_rate == 20.0
        assert stats.corpus_count == 3
        assert stats.corpus_size == 120
        assert stats.last_new_path == 25
        assert stats.crashes == 1
        assert stats.timeouts == 0
        assert stats.health == "crashed"

    def test_libfuzzer_parser_counts_timeout_artifacts(self) -> None:
        from backend.fuzzing.engines.libfuzzer.stats import LibFuzzerStats

        stats = LibFuzzerStats.parse("#7 pulse corp: 2/17b exec/s: 3\nSUMMARY: libFuzzer: timeout\n")
        assert stats.execution_count == 7
        assert stats.timeouts == 1
        assert stats.crashes == 0
        assert stats.health == "timed_out"

    def test_libfuzzer_parser_accepts_scaled_corpus_bytes(self) -> None:
        from backend.fuzzing.engines.libfuzzer.stats import LibFuzzerStats

        stats = LibFuzzerStats.parse("#9 pulse corp: 2/3Kb exec/s: 4\n")

        assert stats.corpus_size == 3 * 1024

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
    def test_libfuzzer_parser_rejects_non_finite_rates(self, value: str) -> None:
        from backend.fuzzing.engines.libfuzzer.stats import LibFuzzerStats

        with pytest.raises(ValueError, match="finite"):
            LibFuzzerStats.parse(f"#9 pulse corp: 2/3b exec/s: {value}\n")
