"""Engine-native corpus minimisation with clean-coverage preservation."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from uuid import uuid4


@dataclass(frozen=True)
class CorpusCampaign:
    engine: str
    corpus_dir: Path
    target_command: tuple[str, ...]


@dataclass(frozen=True)
class CorpusResult:
    replaced: bool
    reason: str
    before_count: int
    after_count: int
    commands: tuple[tuple[str, ...], ...]


class NativeCorpusRunner(Protocol):
    def run(self, campaign: CorpusCampaign, command: tuple[str, ...], output: Path) -> None: ...


class CorpusMinimiser:
    def __init__(
        self,
        runner: NativeCorpusRunner,
        clean_coverage_probe: Callable[[CorpusCampaign, Path], frozenset[str]],
    ):
        self._runner = runner
        self._clean_coverage_probe = clean_coverage_probe

    def minimise(self, campaign: CorpusCampaign) -> CorpusResult:
        corpus = campaign.corpus_dir
        if corpus.is_symlink() or not corpus.is_dir():
            raise ValueError("campaign corpus must be a regular directory")
        if "build-contexts" in corpus.parts:
            raise ValueError("corpus content cannot be stored in an image build context")
        if not campaign.target_command:
            raise ValueError("target command cannot be empty")

        before_files = self._corpus_files(corpus)
        before_coverage = self._clean_coverage_probe(campaign, corpus)
        token = uuid4().hex
        staging = corpus.with_name(f"{corpus.name}.minimising-{token}")
        commands: list[tuple[str, ...]] = []
        candidate = staging
        try:
            if campaign.engine == "afl++":
                cmin = (
                    "afl-cmin", "-i", "/campaign/corpus", "-o", "/campaign/minimised",
                    "--", *campaign.target_command,
                )
                commands.append(cmin)
                self._runner.run(campaign, cmin, staging)
                selected = self._corpus_files(staging)
                tmin_dir = corpus.with_name(f"{corpus.name}.tmin-{token}")
                for source in selected:
                    relative = source.relative_to(staging)
                    output = tmin_dir / relative
                    command = (
                        "afl-tmin", "-i", f"/campaign/minimised/{relative.as_posix()}",
                        "-o", f"/campaign/tmin/{relative.as_posix()}", "--", *campaign.target_command,
                    )
                    commands.append(command)
                    self._runner.run(campaign, command, output)
                shutil.rmtree(staging)
                candidate = tmin_dir
            elif campaign.engine == "libfuzzer":
                command = (
                    *campaign.target_command, "-merge=1", "/campaign/minimised", "/campaign/corpus",
                )
                commands.append(command)
                self._runner.run(campaign, command, staging)
            else:
                raise ValueError(f"unsupported corpus engine: {campaign.engine}")

            candidate_files = self._corpus_files(candidate)
            if not candidate_files:
                return CorpusResult(False, "native minimiser produced an empty corpus", len(before_files), 0, tuple(commands))
            candidate_coverage = self._clean_coverage_probe(campaign, candidate)
            if not before_coverage.issubset(candidate_coverage):
                return CorpusResult(
                    False,
                    "minimised corpus did not preserve clean coverage",
                    len(before_files),
                    len(candidate_files),
                    tuple(commands),
                )
            self._replace_corpus(corpus, candidate)
            candidate = corpus
            return CorpusResult(
                True,
                "clean coverage preserved",
                len(before_files),
                len(self._corpus_files(corpus)),
                tuple(commands),
            )
        finally:
            for temporary in (staging, corpus.with_name(f"{corpus.name}.tmin-{token}")):
                if temporary.exists() and not temporary.is_symlink():
                    shutil.rmtree(temporary)

    @staticmethod
    def _corpus_files(root: Path) -> tuple[Path, ...]:
        if root.is_symlink() or not root.is_dir():
            raise ValueError("native minimiser did not produce a regular corpus directory")
        entries = tuple(sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()))
        if any(entry.is_symlink() for entry in entries):
            raise ValueError("corpus directories cannot contain symlinks")
        return tuple(entry for entry in entries if entry.is_file())

    @staticmethod
    def _replace_corpus(corpus: Path, candidate: Path) -> None:
        backup = corpus.with_name(f"{corpus.name}.before-minimisation")
        if backup.exists() or backup.is_symlink():
            raise ValueError("stale corpus backup must be reviewed before minimisation")
        corpus.rename(backup)
        try:
            candidate.rename(corpus)
        except BaseException:
            backup.rename(corpus)
            raise
        shutil.rmtree(backup)
