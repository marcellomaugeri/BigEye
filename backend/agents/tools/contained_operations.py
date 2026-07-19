"""Validated requests for deterministic container operations; never a host shell."""

from pathlib import PurePosixPath

from agents import RunContextWrapper, function_tool

from backend.agents.context import AgentContext
from backend.agents.tools.generated_assets import _relative_path


_OPERATIONS = frozenset({"build", "probe", "replay", "coverage"})


def contained_operation_request(
    context: AgentContext, operation: str, asset_paths: list[str], assertions: list[str]
) -> dict[str, object]:
    """Validate an operation request for a later deterministic coordinator."""
    if operation not in _OPERATIONS:
        raise ValueError("contained operation is not allowed")
    if not isinstance(asset_paths, list) or not 1 <= len(asset_paths) <= 16:
        raise ValueError("contained operation requires bounded generated assets")
    safe_paths: list[str] = []
    for value in asset_paths:
        path = _relative_path(value)
        candidate = context.generated_assets_root.joinpath(*PurePosixPath(path).parts)
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("contained operation asset is not a generated regular file")
        try:
            candidate.resolve(strict=True).relative_to(context.generated_assets_root.resolve(strict=True))
        except (FileNotFoundError, ValueError) as error:
            raise ValueError("contained operation asset escaped its generated root") from error
        safe_paths.append(path.as_posix())
    if (
        not isinstance(assertions, list) or not 1 <= len(assertions) <= 16
        or any(not isinstance(value, str) or not value.strip() or len(value) > 500 for value in assertions)
    ):
        raise ValueError("contained operation assertions are invalid")
    return {
        "operation": operation, "asset_paths": safe_paths, "assertions": assertions,
        "executed": False, "provenance": "agent_request", "trusted_instructions": False,
    }


@function_tool(name_override="request_contained_operation", failure_error_function=None)
async def request_contained_operation(
    context: RunContextWrapper[AgentContext], operation: str, asset_paths: list[str], assertions: list[str]
) -> dict[str, object]:
    """Request a bounded build, probe, replay, or coverage job from deterministic services."""
    return contained_operation_request(context.context, operation, asset_paths, assertions)


def contained_operation_tools() -> list:
    return [request_contained_operation]
