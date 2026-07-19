# Task 7 report: reusable campaign layers

## Delivered

- Added atomic, project-contained asset publication. Files are verified regular non-symlink sources within the project workspace before persistence; declared and copied-content hashes are checked; staging and directories are fsynced; publication uses an atomic rename; and the persisted row is marked validated only afterwards. Failed post-persistence writes record an asset error and remove staging. Host files use mode `0600`, except contained generated `.sh` scripts, which use `0700`.
- Extended `AssetRepository` with the minimal `create`, `mark_validated`, and `record_error` operations needed by `AssetStore`.
- Added strict continuation-aware Dockerfile validation and reusable project, target, and clean-coverage layer services. Contexts are atomic, content addressed, built from validated same-project asset IDs, verify content hashes, preserve the Task 6 `LayerManifest` and inspect matching linux/amd64 labels before reuse.
- Project layers are the only generated layers permitted build-time network access. Target and coverage builds pass `network_mode="none"` at the Docker SDK boundary. Target identity can include an optional fuzz-only patch asset while excluding corpus, runtime-only, and dictionary inputs; clean coverage rejects explicit fuzz patches.
- Extended `ImageBuilder.build` with an optional `network_mode` without changing existing calls.

## Test evidence

```text
backend/.venv/bin/python -m pytest backend/tests/test_campaign_assets.py backend/tests/test_incremental_layers.py backend/tests/test_fuzzing_docker.py -q
36 passed in 0.49s

backend/.venv/bin/python -m compileall -q backend/fuzzing/assets backend/fuzzing/layers backend/repositories/asset_repository.py backend/fuzzing/docker/image_builder.py
git diff --check
both passed

backend/.venv/bin/python -m pytest backend/tests -q
208 passed in 2.45s
```

The complete backend suite was rerun after Task 8 supplied its discovery and evidence modules.

## Live Docker smoke evidence

Built against cached `bigeye-repository:ca7417fd25b2c301900c` and inspected each result:

```text
SMOKE project bigeye-project:99e1c7da2e962851a2d2 linux/amd64 project
SMOKE target bigeye-target:9ca169ae2b3ab8a6dc45 linux/amd64 target
SMOKE coverage bigeye-coverage:ae4321d9dfb3556d8eaf linux/amd64 coverage
```

Docker reported expected emulation warnings on the arm64 host while each inspected output was `linux/amd64`.
