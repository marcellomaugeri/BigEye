"""Clean-source coverage replay layers isolated from fuzz-only modifications."""

from __future__ import annotations

from backend.fuzzing.layers.policy import LayerPolicy
from backend.fuzzing.layers.project_layer import _GeneratedLayerService


class CoverageLayerService(_GeneratedLayerService):
    _kind = "coverage"
    _parent_kind = "project"
    _network_allowed = False
    _dockerfile_asset_index = 0

    def prepare(
        self, project, project_manifest, adapter_asset, coverage_configuration, sink,
        *, target_asset_id, configuration_asset_id, coverage_asset_id,
        cancellation_signal=None,
    ):
        identities = {
            "bigeye.target-asset-id": target_asset_id,
            "bigeye.configuration-asset-id": configuration_asset_id,
            "bigeye.coverage-asset-id": coverage_asset_id,
        }
        if any(type(value) is not int or value <= 0 for value in identities.values()):
            raise ValueError("coverage provenance asset ID must be a positive integer")
        LayerPolicy().validate_coverage_inputs((
            (adapter_asset.name, adapter_asset.kind), (coverage_configuration.name, coverage_configuration.kind),
        ))
        configuration_name = self._asset_entrypoint(coverage_configuration)
        template = (
            "FROM {parent}\nWORKDIR /src\nCOPY adapter/ /bigeye/adapter/\n"
            "COPY coverage-configuration/ /bigeye/coverage-configuration/\n"
            "RUN /bin/sh /bigeye/coverage-configuration/" + configuration_name + "\n"
            f"LABEL bigeye.project=\"{project.id}\" bigeye.commit=\"{project.commit_sha}\" "
            "bigeye.layer=\"coverage\" bigeye.content-hash=\"{content_hash}\" "
            "bigeye.parent-image=\"{parent_image}\"\n"
        )
        return self._prepare(
            project, project_manifest,
            (("adapter", adapter_asset), ("coverage-configuration", coverage_configuration)), template, sink, "none",
            cancellation_signal=cancellation_signal,
            extra_labels={key: str(value) for key, value in identities.items()},
        )
