"""Deterministic local retrieval over bounded repository evidence."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from itertools import islice
import io
import os
from pathlib import Path
import re

from backend.agents.tools.code_navigation import (
    CodeNavigationError,
    _open_contained_file,
    _opened_repository_root,
    _read_open_text,
    _relative_parts,
    _repository_root,
)
from backend.fuzzing.discovery.inventory import Inventory, MAX_EVIDENCE_FILE_BYTES, MAX_EVIDENCE_BYTES, RepositoryInventory


MAX_QUESTION_LENGTH = 200
MAX_RESULTS = 12
MAX_EXCERPT_CHARS = 600
MAX_MATCHED_LINES = 4_096
MAX_CANDIDATES = 256


@dataclass(frozen=True)
class EvidenceExcerpt:
    evidence_id: str
    path: str
    start_line: int
    end_line: int
    excerpt: str
    reason: str
    provenance: str = "repository"
    trusted_instructions: bool = False

    def as_dict(self) -> dict[str, int | str | bool]:
        return {
            "evidence_id": self.evidence_id,
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "excerpt": self.excerpt,
            "reason": self.reason,
            "provenance": self.provenance,
            "trusted_instructions": self.trusted_instructions,
        }


class EvidenceRetriever:
    """Rank lexical and structural evidence without remote indexing or execution."""

    def __init__(self, repository_root: Path, inventory: Inventory | None = None):
        self.repository_root = _repository_root(Path(repository_root))
        self.inventory = inventory or RepositoryInventory().collect(self.repository_root)

    def search(self, question: str, limit: int = MAX_RESULTS) -> list[EvidenceExcerpt]:
        if not isinstance(question, str) or not question.strip() or "\x00" in question or len(question) > MAX_QUESTION_LENGTH:
            raise CodeNavigationError("evidence question is outside the allowed bounds")
        if not isinstance(limit, int) or limit < 1 or limit > MAX_RESULTS:
            raise CodeNavigationError("evidence result limit is outside the allowed bounds")
        terms = tuple(dict.fromkeys(re.findall(r"[A-Za-z0-9_./:+-]{2,}", question.casefold())))
        if not terms:
            raise CodeNavigationError("evidence question is outside the allowed bounds")
        candidates: list[tuple[int, str, int, int, str, str]] = []
        remaining = MAX_EVIDENCE_BYTES
        remaining_lines = MAX_MATCHED_LINES
        remaining_candidates = MAX_CANDIDATES
        try:
            with _opened_repository_root(self.repository_root) as (_, descriptor):
                for relative_path in sorted(self.inventory.text_files)[:256]:
                    if remaining_lines <= 0 or remaining_candidates <= 0:
                        break
                    content, consumed = self._bounded_text(descriptor, relative_path, remaining)
                    remaining -= consumed
                    if content is None:
                        continue
                    matched, examined = self._matches(
                        relative_path,
                        content,
                        terms,
                        remaining_lines,
                        remaining_candidates,
                    )
                    candidates.extend(matched)
                    remaining_lines -= examined
                    remaining_candidates -= len(matched)
        except (CodeNavigationError, OSError):
            return []
        candidates.sort(key=lambda candidate: (-candidate[0], candidate[1], candidate[2], candidate[4]))
        return [self._excerpt(candidate) for candidate in candidates[:limit]]

    @staticmethod
    def _bounded_text(root_descriptor: int, relative_path: str, remaining: int) -> tuple[str | None, int]:
        try:
            descriptor = _open_contained_file(root_descriptor, _relative_parts(relative_path))
        except (CodeNavigationError, OSError):
            return None, 0
        try:
            size = os.fstat(descriptor).st_size
            if size > MAX_EVIDENCE_FILE_BYTES or size > remaining:
                return None, 0
            content = _read_open_text(descriptor)
        except (CodeNavigationError, OSError):
            return None, 0
        finally:
            os.close(descriptor)
        return content, len(content.encode("utf-8"))

    def _matches(
        self,
        relative_path: str,
        content: str,
        terms: tuple[str, ...],
        line_limit: int,
        candidate_limit: int,
    ) -> tuple[list[tuple[int, str, int, int, str, str]], int]:
        path_lower = relative_path.casefold()
        path_terms = tuple(term for term in terms if term in path_lower)
        matches: list[tuple[int, str, int, int, str, str]] = []
        examined = 0
        phrase = " ".join(terms)
        for line_number, raw_line in enumerate(islice(io.StringIO(content), line_limit), start=1):
            examined += 1
            line = raw_line.rstrip("\r\n")
            lowered = line.casefold()
            line_terms = tuple(term for term in terms if term in lowered)
            if not line_terms and not path_terms:
                continue
            score = 35 * len(path_terms) + 25 * len(line_terms)
            if phrase in lowered:
                score += 40
            reason_parts: list[str] = []
            if path_terms:
                reason_parts.append("path/name match: " + ", ".join(path_terms))
            if line_terms:
                reason_parts.append("literal text match: " + ", ".join(line_terms))
            if relative_path in self.inventory.build_files:
                score += 15
                reason_parts.append("build evidence")
            if Path(relative_path).suffix.casefold() in {".c", ".cc", ".cpp", ".cxx", ".rs", ".go", ".java", ".kt", ".swift", ".py"}:
                score += 10
                reason_parts.append("component source")
            excerpt = line[:MAX_EXCERPT_CHARS]
            matches.append((score, relative_path, line_number, line_number, excerpt, "; ".join(reason_parts)))
            if len(matches) >= candidate_limit:
                break
        return matches, examined

    @staticmethod
    def _excerpt(candidate: tuple[int, str, int, int, str, str]) -> EvidenceExcerpt:
        _, path, start_line, end_line, excerpt, reason = candidate
        evidence_id = sha256(f"{path}\0{start_line}\0{end_line}\0{excerpt}".encode("utf-8")).hexdigest()[:20]
        return EvidenceExcerpt(evidence_id, path, start_line, end_line, excerpt, reason)
