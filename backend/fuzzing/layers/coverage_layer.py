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
        cancellation_signal=None,
    ):
        LayerPolicy().validate_coverage_inputs((
            (adapter_asset.name, adapter_asset.kind), (coverage_configuration.name, coverage_configuration.kind),
        ))
        parent_image = self._inspector.inspect(project_manifest.tag).image_id
        configuration_name = self._asset_entrypoint(coverage_configuration)
        template = (
            "FROM {parent}\nWORKDIR /src\nCOPY adapter/ /bigeye/adapter/\n"
            "COPY coverage-configuration/ /bigeye/coverage-configuration/\n"
            "RUN /bin/sh /bigeye/coverage-configuration/" + configuration_name + "\n"
            f"LABEL bigeye.project=\"{project.id}\" bigeye.commit=\"{project.commit_sha}\" "
            "bigeye.layer=\"coverage\" bigeye.content-hash=\"{content_hash}\" "
            f"bigeye.parent-image=\"{parent_image}\"\n"
        )
        return self._prepare(
            project, project_manifest,
            (("adapter", adapter_asset), ("coverage-configuration", coverage_configuration)), template, sink, "none",
            cancellation_signal,
        )
