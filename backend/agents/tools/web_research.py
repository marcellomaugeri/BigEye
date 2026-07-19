"""Deterministic official-documentation boundaries for specialist web research."""

from __future__ import annotations

from urllib.parse import urlsplit

from agents import WebSearchTool
from openai.types.responses.web_search_tool import Filters

from backend.agents.context import AgentContext


_BASE_TOOL_DOMAINS = frozenset({"aflplus.plus", "llvm.org"})
_BUILD_DOMAIN_MARKERS = (
    (("cmakelists.txt", ".cmake"), "cmake.org"),
    (("meson.build", "meson_options.txt"), "mesonbuild.com"),
    (("cargo.toml", "cargo.lock"), "doc.rust-lang.org"),
    (("build", "build.bazel", "workspace", "workspace.bazel"), "bazel.build"),
    (("pom.xml",), "maven.apache.org"),
    (("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"), "docs.gradle.org"),
    (("makefile", "gnumakefile", "configure.ac", "configure.in"), "gnu.org"),
    (("build.ninja",), "ninja-build.org"),
    (("go.mod",), "go.dev"),
    (("package.swift",), "swift.org"),
)


class UnofficialWebCitation(ValueError):
    """Raised when model output depends on a web source outside the official allowlist."""


def official_documentation_domains(context: AgentContext) -> frozenset[str]:
    """Derive the smallest useful official build/tool domain set from repository inventory."""
    build_files = getattr(context.evidence.inventory, "build_files", ())
    names = {
        str(value).replace("\\", "/").rsplit("/", 1)[-1].casefold()
        for value in build_files if isinstance(value, str)
    }
    domains = set(_BASE_TOOL_DOMAINS)
    for markers, domain in _BUILD_DOMAIN_MARKERS:
        if any(name in markers or any(name.endswith(marker) for marker in markers if marker.startswith(".")) for name in names):
            domains.add(domain)
    return frozenset(domains)


def official_web_search_tool(domains: frozenset[str]) -> WebSearchTool:
    """Restrict hosted web search before any result reaches the specialist."""
    return WebSearchTool(
        search_context_size="low", filters=Filters(allowed_domains=sorted(domains)),
    )


def validate_official_citations(citations: list[str], domains: frozenset[str]) -> list[str]:
    """Accept HTTPS citations only when their hostname is an allowed official domain."""
    accepted: list[str] = []
    for citation in citations:
        try:
            parsed = urlsplit(citation)
            hostname = (parsed.hostname or "").casefold().rstrip(".")
        except ValueError as error:
            raise UnofficialWebCitation("specialist returned a malformed web citation") from error
        if (
            parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or not hostname
            or not any(hostname == domain or hostname.endswith("." + domain) for domain in domains)
        ):
            raise UnofficialWebCitation("specialist cited a nonofficial web source")
        accepted.append(citation)
    return list(dict.fromkeys(accepted))
