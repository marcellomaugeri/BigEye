"""Durable ownership and isolation contracts for long-running fuzzers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest


IMAGE_ID = "sha256:" + "c" * 64


def _campaign(tmp_path: Path, **changes):
    from backend.fuzzing.docker.fuzz_container import FuzzCampaign

    workspace = tmp_path / "campaign-3"
    workspace.mkdir(exist_ok=True)
    values = {
        "id": 3,
        "project_id": 7,
        "commit_sha": "a" * 40,
        "workspace": workspace,
    }
    values.update(changes)
    return FuzzCampaign(**values)


def _invocation(**changes):
    from backend.fuzzing.engines.contracts import ContainerInvocation

    values = {
        "engine": "afl",
        "image_id": IMAGE_ID,
        "command": ["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output", "--", "/opt/bigeye/target"],
        "environment": {"ASAN_OPTIONS": "abort_on_error=1"},
        "campaign_labels": {"bigeye.configuration": "basic"},
        "network_disabled": True,
        "read_only_source": True,
        "timeout_ms": 1_000,
        "memory_limit_mb": 512,
    }
    values.update(changes)
    return ContainerInvocation(**values)


class FakeContainer:
    def __init__(self, container_id="container-3", *, labels=None, image_id=IMAGE_ID, status="created", logs=b"final log\n"):
        self.id = container_id
        self.status = status
        self._logs = logs
        self.attrs = {
            "Id": container_id,
            "Image": image_id,
            "State": {"Status": status},
            "Config": {"Labels": labels or {}},
        }
        self.calls = []

    def start(self):
        self.calls.append(("start",))
        self.status = "running"
        self.attrs["State"]["Status"] = "running"

    def reload(self):
        self.calls.append(("reload",))
        self.attrs["State"]["Status"] = self.status

    def logs(self, **kwargs):
        self.calls.append(("logs", kwargs))
        if kwargs.get("stream"):
            return iter(self._logs.splitlines(keepends=True))
        return self._logs

    def stop(self, timeout):
        self.calls.append(("stop", timeout))
        self.status = "exited"
        self.attrs["State"]["Status"] = "exited"

    def kill(self):
        self.calls.append(("kill",))
        self.status = "exited"
        self.attrs["State"]["Status"] = "exited"

    def remove(self, force=False):
        self.calls.append(("remove", force))


class FakeContainers:
    def __init__(self, listed=()):
        self.listed = list(listed)
        self.created = []
        self.by_id = {container.id: container for container in listed}

    def create(self, image, command, **kwargs):
        container = FakeContainer(labels=kwargs["labels"], image_id=image)
        self.created.append((image, command, kwargs, container))
        self.by_id[container.id] = container
        return container

    def list(self, **kwargs):
        self.list_calls = getattr(self, "list_calls", []) + [kwargs]
        return list(self.listed)

    def get(self, container_id):
        return self.by_id[container_id]


def _expected_labels():
    return {
        "com.bigeye.managed": "fuzz-campaign",
        "com.bigeye.campaign-id": "3",
        "com.bigeye.project-id": "7",
        "com.bigeye.commit-sha": "a" * 40,
        "com.bigeye.image-id": IMAGE_ID,
        "com.bigeye.engine": "afl",
        "bigeye.configuration": "basic",
    }


class TestFuzzContainerStart:
    def test_creates_persistent_container_with_exact_isolation_and_only_campaign_mount(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        containers = FakeContainers()
        identity = FuzzContainerService(SimpleNamespace(containers=containers)).start(_campaign(tmp_path), _invocation())

        image, command, options, container = containers.created[0]
        assert image == IMAGE_ID
        assert command[0] == "afl-fuzz"
        assert options["platform"] == "linux/amd64"
        assert options["network_disabled"] is True
        assert options["privileged"] is False
        assert options["read_only"] is True
        assert options["cap_drop"] == ["ALL"]
        assert options["security_opt"] == ["no-new-privileges"]
        assert options["pids_limit"] == 256
        assert options["mem_limit"] == "512m"
        assert options["nano_cpus"] == 1_000_000_000
        assert options["tmpfs"] == {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"}
        assert options["auto_remove"] is False
        assert options["detach"] is True
        uid, gid = options["user"].split(":")
        assert uid.isdigit() and gid.isdigit()
        workspace = _campaign(tmp_path).workspace.resolve()
        assert options["volumes"] == {
            str(workspace / "corpus"): {"bind": "/campaign/corpus", "mode": "rw"},
            str(workspace / "output"): {"bind": "/campaign/output", "mode": "rw"},
            str(workspace / "config"): {"bind": "/campaign/config", "mode": "ro"},
        }
        assert options["labels"] == _expected_labels()
        assert container.calls == [("start",)]
        assert identity.container_id == "container-3"
        assert identity.expected_labels == _expected_labels()

    def test_never_runs_the_fuzzer_as_root(self, tmp_path: Path, monkeypatch) -> None:
        from backend.fuzzing.docker import fuzz_container
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        monkeypatch.setattr(fuzz_container.os, "getuid", lambda: 0)
        monkeypatch.setattr(fuzz_container.os, "getgid", lambda: 0)
        containers = FakeContainers()

        FuzzContainerService(SimpleNamespace(containers=containers)).start(_campaign(tmp_path), _invocation())

        assert containers.created[0][2]["user"] == "65534:65534"

    @pytest.mark.parametrize(
        "change",
        [
            {"network_disabled": False},
            {"read_only_source": False},
            {"memory_limit_mb": 0},
        ],
    )
    def test_rejects_unsafe_invocation_before_container_creation(self, tmp_path: Path, change) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        containers = FakeContainers()
        with pytest.raises(ValueError):
            FuzzContainerService(SimpleNamespace(containers=containers)).start(_campaign(tmp_path), _invocation(**change))
        assert containers.created == []

    def test_reserved_campaign_label_cannot_be_overridden(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        with pytest.raises(ValueError, match="reserved"):
            FuzzContainerService(SimpleNamespace(containers=FakeContainers())).start(
                _campaign(tmp_path),
                _invocation(campaign_labels={"com.bigeye.commit-sha": "wrong"}),
            )

    def test_rejects_invalid_log_destination_before_creating_a_container(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        campaign = _campaign(tmp_path)
        (campaign.workspace / "logs").write_text("not a directory")
        containers = FakeContainers()

        with pytest.raises(ValueError, match="log path"):
            FuzzContainerService(SimpleNamespace(containers=containers)).start(campaign, _invocation())

        assert containers.created == []


class TestFuzzContainerRecovery:
    def test_adopts_only_running_container_with_exact_campaign_commit_image_and_engine_labels(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        container = FakeContainer(labels=_expected_labels(), status="running")
        containers = FakeContainers([container])

        identity = FuzzContainerService(SimpleNamespace(containers=containers)).recover(_campaign(tmp_path), _invocation())

        assert identity is not None
        assert identity.container_id == container.id
        assert containers.created == []
        assert containers.list_calls == [{"all": True, "filters": {"label": ["com.bigeye.managed=fuzz-campaign", "com.bigeye.campaign-id=3"]}}]

    @pytest.mark.parametrize(
        ("label", "value"),
        [
            ("com.bigeye.commit-sha", "b" * 40),
            ("com.bigeye.image-id", "sha256:other"),
            ("com.bigeye.campaign-id", "4"),
        ],
    )
    def test_rejects_mismatched_container_ownership(self, tmp_path: Path, label: str, value: str) -> None:
        from backend.fuzzing.docker.fuzz_container import ContainerOwnershipMismatch, FuzzContainerService

        labels = _expected_labels()
        labels[label] = value
        container = FakeContainer(labels=labels, status="running")

        with pytest.raises(ContainerOwnershipMismatch):
            FuzzContainerService(SimpleNamespace(containers=FakeContainers([container]))).recover(_campaign(tmp_path), _invocation())

    def test_returns_none_when_no_managed_container_exists(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        assert FuzzContainerService(SimpleNamespace(containers=FakeContainers())).inspect(_campaign(tmp_path), _invocation()) is None


class TestFuzzContainerLifecycle:
    def test_stream_logs_verifies_ownership_and_forwards_text(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        container = FakeContainer(labels=_expected_labels(), status="running", logs=b"one\ntwo\n")
        containers = FakeContainers([container])
        service = FuzzContainerService(SimpleNamespace(containers=containers))
        identity = service.recover(_campaign(tmp_path), _invocation())
        output = []

        service.stream_logs(identity, output.append, follow=False)

        assert output == ["one\n", "two\n"]

    def test_stop_persists_final_logs_then_removes_only_exited_matching_container(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        container = FakeContainer(labels=_expected_labels(), status="running")
        containers = FakeContainers([container])
        service = FuzzContainerService(SimpleNamespace(containers=containers), stop_timeout_seconds=7)
        identity = service.recover(_campaign(tmp_path), _invocation())

        service.stop(identity)

        assert identity.log_path.read_bytes() == b"final log\n"
        assert ("stop", 7) in container.calls
        assert ("kill",) not in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_stop_kills_after_grace_period_and_never_force_removes_a_running_container(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        class StubbornContainer(FakeContainer):
            def stop(self, timeout): self.calls.append(("stop", timeout))

        container = StubbornContainer(labels=_expected_labels(), status="running")
        containers = FakeContainers([container])
        service = FuzzContainerService(SimpleNamespace(containers=containers), stop_timeout_seconds=2)
        identity = service.recover(_campaign(tmp_path), _invocation())

        service.stop(identity)

        assert ("stop", 2) in container.calls
        assert ("kill",) in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_stop_refuses_container_whose_labels_changed_after_adoption(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import ContainerOwnershipMismatch, FuzzContainerService

        container = FakeContainer(labels=_expected_labels(), status="running")
        containers = FakeContainers([container])
        service = FuzzContainerService(SimpleNamespace(containers=containers))
        identity = service.recover(_campaign(tmp_path), _invocation())
        container.attrs["Config"]["Labels"]["com.bigeye.image-id"] = "sha256:swapped"

        with pytest.raises(ContainerOwnershipMismatch):
            service.stop(identity)
        assert not any(call[0] in {"stop", "kill", "remove"} for call in container.calls)
