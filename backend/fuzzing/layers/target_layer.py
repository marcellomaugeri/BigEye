"""Reusable target compilation layers that never receive build-time network access."""

from __future__ import annotations

from hashlib import sha256

from backend.fuzzing.layers.project_layer import _GeneratedLayerService


class TargetLayerService(_GeneratedLayerService):
    _kind = "target"
    _parent_kind = "project"
    _network_allowed = False

    @staticmethod
    def tag(
        *, harness_hash: str, build_hash: str, corpus_hash: str | None = None, fuzz_patch_hash: str | None = None
    ) -> str:
        """Return identity for compile inputs only; corpus is intentionally excluded."""
        return "bigeye-target:" + sha256(f"{harness_hash}\0{build_hash}\0{fuzz_patch_hash or ''}".encode()).hexdigest()[:20]

    def prepare(self, project, project_manifest, target_asset, configuration_asset, sink, fuzz_patch_asset=None):
        parent_image = self._inspector.inspect(project_manifest.tag).image_id
        configuration_name = self._asset_entrypoint(configuration_asset)
        assets = [("target", target_asset), ("configuration", configuration_asset)]
        patch_steps = ""
        if fuzz_patch_asset is not None:
            patch_name = self._asset_entrypoint(fuzz_patch_asset)
            assets.append(("fuzz-patch", fuzz_patch_asset))
            patch_steps = f"COPY fuzz-patch/ /bigeye/fuzz-patch/\nRUN patch -p1 < /bigeye/fuzz-patch/{patch_name}\n"
        template = (
            "FROM {parent}\nWORKDIR /src\nCOPY target/ /bigeye/target/\n"
            "COPY configuration/ /bigeye/configuration/\n"
            + patch_steps + "RUN /bin/sh /bigeye/configuration/" + configuration_name + "\n"
            f"LABEL bigeye.project=\"{project.id}\" bigeye.commit=\"{project.commit_sha}\" "
            "bigeye.layer=\"target\" bigeye.content-hash=\"{content_hash}\" "
            f"bigeye.parent-image=\"{parent_image}\"\n"
        )
        return self._prepare(
            project, project_manifest, tuple(assets), template, sink, "none"
        )
