"""Adversarial ownership and isolation contracts for long-running fuzzers."""

from __future__ import annotations

import time
from pathlib import Path

import pytest


IMAGE_ID = "sha256:" + "c" * 64
BASE_ENVIRONMENT = {"PATH": "/usr/local/bin:/usr/bin"}
BASE_LABELS = {"bigeye.layer": "target"}


def _campaign():
    from backend.fuzzing.docker.fuzz_container import FuzzCampaign

    return FuzzCampaign(id=3, project_id=7, commit_sha="a" * 40)


def _invocation(**changes):
    from backend.fuzzing.engines.contracts import ContainerInvocation

    values = {
        "engine": "afl",
        "image_id": IMAGE_ID,
        "command": [
            "afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output",
            "-M", "main", "-t", "1000+", "-m", "0", "--", "/opt/bigeye/target", "@@",
        ],
        "environment": {"ASAN_OPTIONS": "abort_on_error=1:symbolize=0", "AFL_NO_UI": "1"},
        "campaign_labels": {"bigeye.configuration": "basic"},
        "network_disabled": True,
        "read_only_source": True,
        "timeout_ms": 1_000,
        "memory_limit_mb": 512,
    }
    values.update(changes)
    return ContainerInvocation(**values)


class FakeApi:
    def __init__(self):
        self.os = "linux"
        self.architecture = "amd64"

    def inspect_image(self, image_id):
        assert image_id == IMAGE_ID
        return {
            "Id": IMAGE_ID,
            "Os": self.os,
            "Architecture": self.architecture,
            "Config": {"Env": [f"{key}={value}" for key, value in BASE_ENVIRONMENT.items()], "Labels": dict(BASE_LABELS)},
        }


class FakeContainer:
    def __init__(
        self,
        container_id="container-3",
        *,
        attrs=None,
        status="created",
        logs=b"final log\n",
        start_error=None,
        start_status="running",
        log_delay=0.0,
    ):
        self.id = container_id
        self.status = status
        self.attrs = attrs or {}
        self.attrs.setdefault("State", {})["Status"] = status
        self._logs = logs
        self._start_error = start_error
        self._start_status = start_status
        self._log_delay = log_delay
        self.calls = []
        self.removed = False

    def start(self):
        self.calls.append(("start",))
        self.status = self._start_status
        self.attrs["State"]["Status"] = self.status
        if self._start_error is not None:
            raise self._start_error

    def reload(self):
        self.calls.append(("reload",))
        self.attrs["State"]["Status"] = self.status

    def logs(self, **kwargs):
        self.calls.append(("logs", kwargs))

        def chunks():
            if self._log_delay:
                time.sleep(self._log_delay)
            for line in self._logs.splitlines(keepends=True) or [self._logs]:
                yield line

        return chunks() if kwargs.get("stream") else self._logs

    def stop(self, timeout):
        self.calls.append(("stop", timeout))
        self.status = "exited"
        self.attrs["State"]["Status"] = "exited"

    def pause(self):
        self.calls.append(("pause",))
        self.status = "paused"
        self.attrs["State"]["Status"] = "paused"

    def unpause(self):
        self.calls.append(("unpause",))
        self.status = "running"
        self.attrs["State"]["Status"] = "running"

    def kill(self):
        self.calls.append(("kill",))
        self.status = "exited"
        self.attrs["State"]["Status"] = "exited"

    def remove(self, force=False):
        self.calls.append(("remove", force))
        self.removed = True


class FakeContainers:
    def __init__(self):
        self.listed = []
        self.created = []
        self.by_id = {}
        self.next_start_error = None
        self.next_start_status = "running"
        self.next_logs = b"final log\n"
        self.next_log_delay = 0.0
        self.next_stop_error = None
        self.next_kill_error = None

    def create(self, image, command, **options):
        container_id = f"container-{len(self.created) + 3}"
        environment = dict(BASE_ENVIRONMENT)
        environment.update(options["environment"])
        labels = dict(BASE_LABELS)
        labels.update(options["labels"])
        mounts = [
            {
                "Type": "bind", "Source": source, "Destination": mount["bind"],
                "Mode": mount["mode"], "RW": mount["mode"] == "rw",
            }
            for source, mount in options["volumes"].items()
        ]
        attrs = {
            "Id": container_id,
            "Image": image,
            "Platform": "linux",
            "Name": f"/{options['name']}",
            "Config": {
                "Cmd": list(command),
                "Env": [f"{key}={value}" for key, value in environment.items()],
                "Labels": labels,
                "User": options["user"],
                "NetworkDisabled": options["network_disabled"],
                "ExposedPorts": None,
            },
            "HostConfig": {
                "NetworkMode": options["network_mode"],
                "Runtime": options["runtime"],
                "Privileged": options["privileged"],
                "ReadonlyRootfs": options["read_only"],
                "CapDrop": list(options["cap_drop"]),
                "CapAdd": [],
                "SecurityOpt": list(options["security_opt"]),
                "PidsLimit": options["pids_limit"],
                "Memory": int(options["mem_limit"].removesuffix("m")) * 1024 * 1024,
                "NanoCpus": options["nano_cpus"],
                "Tmpfs": dict(options["tmpfs"]),
                "AutoRemove": options["auto_remove"],
                "Devices": None,
                "DeviceRequests": None,
                "PortBindings": {},
                "PublishAllPorts": options["publish_all_ports"],
                "RestartPolicy": {"MaximumRetryCount": 0, **options["restart_policy"]},
                "PidMode": "",
                "IpcMode": options["ipc_mode"],
                "UTSMode": "",
                "UsernsMode": "",
                "CgroupnsMode": options["cgroupns"],
                "Dns": None,
                "DnsOptions": None,
                "DnsSearch": None,
                "ExtraHosts": None,
                "Links": None,
                "GroupAdd": None,
                "OomKillDisable": False,
                "CgroupParent": "",
                "Isolation": "",
                "DeviceCgroupRules": None,
                "Sysctls": None,
                "Ulimits": None,
                "VolumesFrom": None,
            },
            "Mounts": mounts,
            "NetworkSettings": {"Networks": {}},
        }
        container = FakeContainer(
            container_id=container_id,
            attrs=attrs,
            logs=self.next_logs,
            start_error=self.next_start_error,
            start_status=self.next_start_status,
            log_delay=self.next_log_delay,
        )
        if self.next_stop_error is not None:
            error = self.next_stop_error
            container.stop = lambda timeout: (_ for _ in ()).throw(error)
        if self.next_kill_error is not None:
            error = self.next_kill_error
            container.kill = lambda: (_ for _ in ()).throw(error)
        self.created.append((image, command, options, container))
        self.listed.append(container)
        self.by_id[container.id] = container
        return container

    def list(self, **kwargs):
        self.list_calls = getattr(self, "list_calls", []) + [kwargs]
        return [container for container in self.listed if not container.removed]

    def get(self, container_id):
        return self.by_id[container_id]


class FakeClient:
    def __init__(self, containers=None):
        self.containers = containers or FakeContainers()
        self.api = FakeApi()


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir(exist_ok=True)
    return root


def _service(tmp_path: Path, client=None, **settings):
    from backend.fuzzing.docker.fuzz_container import FuzzContainerService

    client = client or FakeClient()
    return FuzzContainerService(client, _workspace(tmp_path), **settings), client


def _campaign_path(root: Path) -> Path:
    return root / "projects" / "7" / "campaigns" / "3"


class TestFuzzContainerStart:
    def test_creates_exact_persistent_isolation_and_reloads_before_return(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)

        identity = service.start(_campaign(), _invocation())

        image, command, options, container = client.containers.created[0]
        workspace = _campaign_path(_workspace(tmp_path))
        mount_labels = {}
        for name in ("corpus", "output", "config"):
            mount_stat = (workspace / name).stat()
            mount_labels[f"com.bigeye.mount.{name}"] = f"{mount_stat.st_dev}:{mount_stat.st_ino}"
        assert image == IMAGE_ID and command == _invocation().command
        assert options == {
            "name": "bigeye-campaign-3",
            "platform": "linux/amd64",
            "network_disabled": True,
            "network_mode": "none",
            "ipc_mode": "private",
            "cgroupns": "private",
            "runtime": "runc",
            "restart_policy": {"Name": "no"},
            "publish_all_ports": False,
            "privileged": False,
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges"],
            "user": options["user"],
            "pids_limit": 256,
            "mem_limit": "512m",
            "nano_cpus": 1_000_000_000,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"},
            "volumes": {
                str(workspace / "corpus"): {"bind": "/campaign/corpus", "mode": "rw"},
                str(workspace / "output"): {"bind": "/campaign/output", "mode": "rw"},
                str(workspace / "config"): {"bind": "/campaign/config", "mode": "ro"},
            },
            "environment": _invocation().environment,
            "labels": {
                "com.bigeye.managed": "fuzz-campaign",
                "com.bigeye.campaign-id": "3",
                "com.bigeye.project-id": "7",
                "com.bigeye.commit-sha": "a" * 40,
                "com.bigeye.image-id": IMAGE_ID,
                "com.bigeye.engine": "afl",
                "bigeye.configuration": "basic",
                **mount_labels,
            },
            "auto_remove": False,
            "detach": True,
        }
        assert options["user"].split(":")[0] != "0"
        assert container.calls[:2] == [("start",), ("reload",)]
        assert identity.container_id == "container-3"

    def test_service_requires_an_explicit_real_workspace_root(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        with pytest.raises(TypeError):
            FuzzContainerService(FakeClient())
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "linked-workspace"
        link.symlink_to(real, target_is_directory=True)
        with pytest.raises(ValueError, match="symlink"):
            FuzzContainerService(FakeClient(), link)

    def test_never_runs_the_fuzzer_as_root(self, tmp_path: Path, monkeypatch) -> None:
        from backend.fuzzing.docker import fuzz_container

        monkeypatch.setattr(fuzz_container.os, "getuid", lambda: 0)
        monkeypatch.setattr(fuzz_container.os, "getgid", lambda: 0)
        service, client = _service(tmp_path)

        service.start(_campaign(), _invocation())

        assert client.containers.created[0][2]["user"] == "65534:65534"

    @pytest.mark.parametrize(
        "command",
        [
            ["afl-fuzz", "--", "/opt/bigeye/target"],
            ["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output", "-M", "main", "-t", "1000+", "-m", "0", "--", "/opt/bigeye/../bin/sh"],
            ["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output", "-M", "main", "-t", "1000+", "-m", "0", "--", "/opt/bigeye/bash", "-c", "id"],
            ["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output", "-M", "main", "-t", "1000+", "-m", "512", "--", "/opt/bigeye/target"],
            ["afl-fuzz", "-i", "/campaign/corpus", "-o", "/campaign/output", "-M", "main", "-t", "1000+", "-m", "0", "--", "--", "/opt/bigeye/target"],
        ],
    )
    def test_rejects_smuggled_or_noncanonical_afl_commands(self, tmp_path: Path, command) -> None:
        service, client = _service(tmp_path)

        with pytest.raises(ValueError, match="AFL"):
            service.start(_campaign(), _invocation(command=command))

        assert client.containers.created == []

    @pytest.mark.parametrize(
        "command",
        [
            ["/opt/bigeye/bash", "-c", "id", "/campaign/corpus", "-artifact_prefix=/campaign/output/", "-timeout=1", "-rss_limit_mb=512"],
            ["/opt/bigeye/../target", "/campaign/corpus", "-artifact_prefix=/campaign/output/", "-timeout=1", "-rss_limit_mb=512"],
            ["/opt/bigeye/target", "/campaign/corpus", "-artifact_prefix=/tmp/", "-timeout=1", "-rss_limit_mb=512"],
        ],
    )
    def test_rejects_smuggled_or_noncanonical_libfuzzer_commands(self, tmp_path: Path, command) -> None:
        service, client = _service(tmp_path)
        invocation = _invocation(engine="libfuzzer", command=command, environment={})

        with pytest.raises(ValueError, match="libFuzzer"):
            service.start(_campaign(), invocation)

        assert client.containers.created == []

    def test_recovers_deterministically_when_start_raises_after_running(self, tmp_path: Path) -> None:
        client = FakeClient()
        client.containers.next_start_error = RuntimeError("daemon disconnected")
        client.containers.next_start_status = "running"
        service, _ = _service(tmp_path, client)

        with pytest.raises(RuntimeError, match="daemon disconnected"):
            service.start(_campaign(), _invocation())

        container = client.containers.created[0][3]
        assert ("stop", 10) in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_start_failure_removes_never_started_container_without_force(self, tmp_path: Path) -> None:
        client = FakeClient()
        client.containers.next_start_error = RuntimeError("start rejected")
        client.containers.next_start_status = "created"
        client.containers.next_stop_error = RuntimeError("cannot stop created")
        client.containers.next_kill_error = RuntimeError("cannot kill created")
        service, _ = _service(tmp_path, client)

        with pytest.raises(RuntimeError, match="start rejected"):
            service.start(_campaign(), _invocation())

        assert client.containers.created[0][3].calls[-1] == ("remove", False)


class TestWorkspaceContainment:
    def test_rejects_symlinked_project_ancestor_before_container_creation(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        (root / "projects").symlink_to(outside, target_is_directory=True)
        service, client = _service(tmp_path)

        with pytest.raises(ValueError, match="symlink"):
            service.start(_campaign(), _invocation())

        assert client.containers.created == []

    def test_rejects_campaign_path_swap_while_descriptor_is_held(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import FuzzContainerService

        root = _workspace(tmp_path)

        class SwappingService(FuzzContainerService):
            def _after_campaign_opened(self, descriptor, campaign_path):
                moved = campaign_path.with_name("3-moved")
                campaign_path.rename(moved)
                campaign_path.mkdir()

        client = FakeClient()
        service = SwappingService(client, root)

        with pytest.raises(ValueError, match="changed"):
            service.start(_campaign(), _invocation())

        assert client.containers.created == []

    def test_rechecks_mount_inodes_immediately_before_container_create(self, tmp_path: Path, monkeypatch) -> None:
        service, client = _service(tmp_path)
        original = service._workspace.require_mount_identities

        def swap_before_check(directory, expected):
            corpus = directory.path / "corpus"
            corpus.rename(corpus.with_name("corpus-moved"))
            corpus.mkdir()
            original(directory, expected)

        monkeypatch.setattr(service._workspace, "require_mount_identities", swap_before_check)

        with pytest.raises(ValueError, match="mount.*changed"):
            service.start(_campaign(), _invocation())

        assert client.containers.created == []

    def test_rechecks_mount_inodes_after_container_start(self, tmp_path: Path, monkeypatch) -> None:
        service, client = _service(tmp_path)
        original = service._workspace.require_mount_identities
        checks = 0

        def swap_on_second_check(directory, expected):
            nonlocal checks
            checks += 1
            if checks == 2:
                output = directory.path / "output"
                output.rename(output.with_name("output-moved"))
                output.mkdir()
            original(directory, expected)

        monkeypatch.setattr(service._workspace, "require_mount_identities", swap_on_second_check)

        with pytest.raises(ValueError, match="mount.*changed"):
            service.start(_campaign(), _invocation())

        container = client.containers.created[0][3]
        assert ("stop", 10) in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_workspace_swap_after_adoption_blocks_stop_and_log_writes(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        campaign_path = _campaign_path(_workspace(tmp_path))
        campaign_path.rename(campaign_path.with_name("3-moved"))
        campaign_path.mkdir()

        with pytest.raises(ValueError, match="changed"):
            service.stop(identity)

        assert not any(call[0] in {"stop", "kill", "remove", "logs"} for call in client.containers.created[0][3].calls[2:])

    def test_mount_directory_swap_blocks_every_container_control(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        corpus = _campaign_path(_workspace(tmp_path)) / "corpus"
        corpus.rename(corpus.with_name("corpus-moved"))
        corpus.mkdir()

        with pytest.raises(ValueError, match="mount.*changed"):
            service.stream_logs(identity, lambda _: None, follow=False)

        container = client.containers.created[0][3]
        assert not any(call[0] in {"logs", "stop", "kill", "remove"} for call in container.calls[2:])

    def test_mount_directory_swap_blocks_fresh_adoption(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        service.start(_campaign(), _invocation())
        output = _campaign_path(_workspace(tmp_path)) / "output"
        output.rename(output.with_name("output-moved"))
        output.mkdir()
        recovered, _ = _service(tmp_path, client)

        with pytest.raises(Exception, match="mount.*changed|contract"):
            recovered.recover(_campaign(), _invocation())

    def test_symlinked_final_log_is_rejected_without_touching_target(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        victim = tmp_path / "victim"
        victim.write_text("safe")
        log_path = _campaign_path(_workspace(tmp_path)) / "logs" / "container.log"
        log_path.symlink_to(victim)

        with pytest.raises(ValueError, match="log"):
            service.stop(identity)

        assert victim.read_text() == "safe"
        assert not any(call[0] in {"stop", "kill", "remove"} for call in client.containers.created[0][3].calls[2:])


class TestFuzzContainerRecovery:
    def test_adopts_only_container_with_complete_service_owned_runtime_contract(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        service.start(_campaign(), _invocation())
        recovered, _ = _service(tmp_path, client)

        identity = recovered.recover(_campaign(), _invocation())

        assert identity is not None and identity.container_id == "container-3"

    def test_incomplete_mandatory_labels_are_rejected(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        service.start(_campaign(), _invocation())
        del client.containers.created[0][3].attrs["Config"]["Labels"]["com.bigeye.engine"]
        recovered, _ = _service(tmp_path, client)

        with pytest.raises(Exception, match="ownership|contract"):
            recovered.recover(_campaign(), _invocation())

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("command", ["afl-fuzz", "--", "/opt/bigeye/target"]),
            ("platform", "windows"),
            ("network", "bridge"),
            ("network_flag", False),
            ("privileged", True),
            ("read_only", False),
            ("mount", "/tmp/foreign"),
            ("memory", 1),
            ("pids", 999),
            ("cpus", 2_000_000_000),
            ("user", "0:0"),
            ("caps", []),
            ("security", []),
            ("tmpfs", {}),
            ("environment", ["PATH=/usr/local/bin:/usr/bin"]),
            ("name", "/forged-name"),
            ("devices", [{"PathOnHost": "/dev/kvm"}]),
            ("device_requests", [{"Driver": "nvidia"}]),
            ("exposed_ports", {"8080/tcp": {}}),
            ("port_bindings", {"8080/tcp": [{"HostPort": "8080"}]}),
            ("publish_ports", True),
            ("restart", {"MaximumRetryCount": 0, "Name": "always"}),
            ("pid_mode", "host"),
            ("ipc_mode", "host"),
            ("uts_mode", "host"),
            ("userns_mode", "host"),
            ("cgroupns_mode", "host"),
            ("dns", ["8.8.8.8"]),
            ("extra_hosts", ["host.docker.internal:host-gateway"]),
            ("links", ["database:database"]),
            ("runtime", "kata-runtime"),
            ("sysctls", {"kernel.shm_rmid_forced": "0"}),
            ("device_rules", ["c 10:200 rwm"]),
        ],
    )
    def test_rejects_any_runtime_contract_drift(self, tmp_path: Path, field: str, value) -> None:
        service, client = _service(tmp_path)
        service.start(_campaign(), _invocation())
        container = client.containers.created[0][3]
        if field == "command": container.attrs["Config"]["Cmd"] = value
        elif field == "platform": container.attrs["Platform"] = value
        elif field == "network": container.attrs["HostConfig"]["NetworkMode"] = value
        elif field == "network_flag": container.attrs["Config"]["NetworkDisabled"] = value
        elif field == "privileged": container.attrs["HostConfig"]["Privileged"] = value
        elif field == "read_only": container.attrs["HostConfig"]["ReadonlyRootfs"] = value
        elif field == "mount": container.attrs["Mounts"][0]["Source"] = value
        elif field == "memory": container.attrs["HostConfig"]["Memory"] = value
        elif field == "pids": container.attrs["HostConfig"]["PidsLimit"] = value
        elif field == "cpus": container.attrs["HostConfig"]["NanoCpus"] = value
        elif field == "user": container.attrs["Config"]["User"] = value
        elif field == "caps": container.attrs["HostConfig"]["CapDrop"] = value
        elif field == "security": container.attrs["HostConfig"]["SecurityOpt"] = value
        elif field == "tmpfs": container.attrs["HostConfig"]["Tmpfs"] = value
        elif field == "environment": container.attrs["Config"]["Env"] = value
        elif field == "name": container.attrs["Name"] = value
        elif field == "devices": container.attrs["HostConfig"]["Devices"] = value
        elif field == "device_requests": container.attrs["HostConfig"]["DeviceRequests"] = value
        elif field == "exposed_ports": container.attrs["Config"]["ExposedPorts"] = value
        elif field == "port_bindings": container.attrs["HostConfig"]["PortBindings"] = value
        elif field == "publish_ports": container.attrs["HostConfig"]["PublishAllPorts"] = value
        elif field == "restart": container.attrs["HostConfig"]["RestartPolicy"] = value
        elif field == "pid_mode": container.attrs["HostConfig"]["PidMode"] = value
        elif field == "ipc_mode": container.attrs["HostConfig"]["IpcMode"] = value
        elif field == "uts_mode": container.attrs["HostConfig"]["UTSMode"] = value
        elif field == "userns_mode": container.attrs["HostConfig"]["UsernsMode"] = value
        elif field == "cgroupns_mode": container.attrs["HostConfig"]["CgroupnsMode"] = value
        elif field == "dns": container.attrs["HostConfig"]["Dns"] = value
        elif field == "extra_hosts": container.attrs["HostConfig"]["ExtraHosts"] = value
        elif field == "links": container.attrs["HostConfig"]["Links"] = value
        elif field == "runtime": container.attrs["HostConfig"]["Runtime"] = value
        elif field == "sysctls": container.attrs["HostConfig"]["Sysctls"] = value
        elif field == "device_rules": container.attrs["HostConfig"]["DeviceCgroupRules"] = value
        recovered, _ = _service(tmp_path, client)

        with pytest.raises(Exception, match="contract"):
            recovered.recover(_campaign(), _invocation())

    def test_rejects_non_amd64_image_during_recovery(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        service.start(_campaign(), _invocation())
        client.api.architecture = "arm64"
        recovered, _ = _service(tmp_path, client)

        with pytest.raises(Exception, match="linux/amd64"):
            recovered.recover(_campaign(), _invocation())

    def test_identity_fields_are_not_accepted_as_ownership_proof(self, tmp_path: Path) -> None:
        from backend.fuzzing.docker.fuzz_container import ContainerIdentity, ContainerOwnershipMismatch

        service, client = _service(tmp_path)
        service.start(_campaign(), _invocation())
        fresh, _ = _service(tmp_path, client)
        forged = ContainerIdentity("container-3", 3, 7, "running")

        with pytest.raises(ContainerOwnershipMismatch, match="unknown"):
            fresh.stream_logs(forged, lambda _: None, follow=False)


class TestFuzzContainerLifecycle:
    def test_owned_runtime_state_survives_an_intentional_quiesced_corpus_swap(
        self, tmp_path: Path,
    ) -> None:
        service, _client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        corpus = _campaign_path(_workspace(tmp_path)) / "corpus"
        corpus.rename(corpus.with_name("retired-corpus"))
        corpus.mkdir()

        observed = service.inspect_owned(identity)

        assert observed.container_id == identity.container_id
        assert observed.state == "running"

    def test_owned_runtime_is_replaced_after_committed_corpus_swap(
        self, tmp_path: Path,
    ) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        log_path = service.log_path(identity)
        old_container = client.containers.created[0][3]
        old_container.pause()
        corpus = _campaign_path(_workspace(tmp_path)) / "corpus"
        corpus.rename(corpus.with_name("retired-corpus"))
        corpus.mkdir()
        committed = corpus.stat()

        replacement = service.replace_owned(
            identity, _campaign(), _invocation(), (committed.st_dev, committed.st_ino),
        )

        container = old_container
        assert ("unpause",) in container.calls
        assert ("stop", 10) in container.calls
        assert container.calls[-1] == ("remove", False)
        assert log_path.read_bytes() == b"final log\n"
        assert replacement.container_id != identity.container_id
        assert len(client.containers.created) == 2
        new_labels = client.containers.created[1][3].attrs["Config"]["Labels"]
        assert new_labels["com.bigeye.mount.corpus"] == (
            f"{committed.st_dev}:{committed.st_ino}"
        )

    @pytest.mark.parametrize("committed_identity", [(0, 1), (1, 0), (True, 1), [1, 2]])
    def test_replacement_rejects_an_invalid_committed_corpus_identity_before_control(
        self, tmp_path: Path, committed_identity,
    ) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        container = client.containers.created[0][3]

        with pytest.raises(ValueError, match="positive"):
            service.replace_owned(
                identity, _campaign(), _invocation(), committed_identity,
            )

        assert not any(
            call[0] in {"unpause", "stop", "kill", "remove", "logs"}
            for call in container.calls[2:]
        )

    def test_stream_logs_rechecks_full_owned_contract(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        output = []

        service.stream_logs(identity, output.append, follow=False)

        assert output == ["final log\n"]

    def test_stop_persists_final_logs_and_removes_only_exited_matching_container(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path, stop_timeout_seconds=7)
        identity = service.start(_campaign(), _invocation())
        log_path = service.log_path(identity)

        service.stop(identity)

        container = client.containers.created[0][3]
        assert log_path.read_bytes() == b"final log\n"
        assert ("stop", 7) in container.calls
        assert ("kill",) not in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_final_logs_are_byte_bounded_with_a_truncation_marker(self, tmp_path: Path) -> None:
        client = FakeClient()
        client.containers.next_logs = b"0123456789abcdefghijklmnopqrstuvwxyz"
        service, _ = _service(tmp_path, client, final_log_max_bytes=8)
        identity = service.start(_campaign(), _invocation())
        log_path = service.log_path(identity)

        service.stop(identity)

        content = log_path.read_bytes()
        assert content.startswith(b"01234567")
        assert b"truncated" in content.lower()
        assert len(content) < 256

    def test_final_logs_are_time_bounded_with_a_truncation_marker(self, tmp_path: Path) -> None:
        client = FakeClient()
        client.containers.next_logs = b"late log"
        client.containers.next_log_delay = 0.2
        service, _ = _service(tmp_path, client, final_log_timeout_seconds=0.01)
        identity = service.start(_campaign(), _invocation())
        log_path = service.log_path(identity)
        started = time.monotonic()

        service.stop(identity)

        assert time.monotonic() - started < 0.15
        assert b"truncated" in log_path.read_bytes().lower()

    def test_stop_kills_after_grace_period_before_nonforce_removal(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path, stop_timeout_seconds=2)
        identity = service.start(_campaign(), _invocation())
        container = client.containers.created[0][3]

        def stubborn_stop(timeout):
            container.calls.append(("stop", timeout))

        container.stop = stubborn_stop
        service.stop(identity)

        assert ("stop", 2) in container.calls
        assert ("kill",) in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_stop_error_is_preserved_after_kill_and_safe_cleanup(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        container = client.containers.created[0][3]

        def failing_stop(timeout):
            container.calls.append(("stop", timeout))
            raise RuntimeError("graceful stop failed")

        container.stop = failing_stop

        with pytest.raises(RuntimeError, match="graceful stop failed"):
            service.stop(identity)

        assert ("kill",) in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_stop_error_after_exit_is_preserved_after_safe_cleanup_without_kill(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        container = client.containers.created[0][3]

        def exited_then_errored(timeout):
            container.calls.append(("stop", timeout))
            container.status = "exited"
            raise RuntimeError("daemon reply was lost")

        container.stop = exited_then_errored

        with pytest.raises(RuntimeError, match="daemon reply was lost"):
            service.stop(identity)

        assert ("kill",) not in container.calls
        assert container.calls[-1] == ("remove", False)

    def test_stop_and_kill_errors_are_combined_without_unsafe_cleanup(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        container = client.containers.created[0][3]

        def failing_stop(timeout):
            container.calls.append(("stop", timeout))
            raise RuntimeError("graceful stop failed")

        def failing_kill():
            container.calls.append(("kill",))
            raise RuntimeError("forced kill failed")

        container.stop = failing_stop
        container.kill = failing_kill

        with pytest.raises(RuntimeError, match="graceful stop failed") as error:
            service.stop(identity)

        assert any("forced kill failed" in note for note in getattr(error.value, "__notes__", []))
        assert not any(call[0] in {"logs", "remove"} for call in container.calls[2:])

    @pytest.mark.parametrize(
        "settings",
        [
            {"stop_timeout_seconds": True},
            {"stop_timeout_seconds": 1.0},
            {"final_log_max_bytes": False},
            {"final_log_max_bytes": 8.0},
            {"final_log_timeout_seconds": True},
            {"final_log_timeout_seconds": 1},
        ],
    )
    def test_service_rejects_wrong_numeric_types(self, tmp_path: Path, settings) -> None:
        with pytest.raises(ValueError):
            _service(tmp_path, **settings)

    @pytest.mark.parametrize(
        "change",
        [
            {"timeout_ms": True},
            {"timeout_ms": 1000.0},
            {"memory_limit_mb": False},
            {"memory_limit_mb": 512.0},
        ],
    )
    def test_service_rejects_non_integer_invocation_resources(self, tmp_path: Path, change) -> None:
        service, client = _service(tmp_path)

        with pytest.raises(ValueError):
            service.start(_campaign(), _invocation(**change))

        assert client.containers.created == []

    def test_stop_refuses_runtime_changed_after_adoption(self, tmp_path: Path) -> None:
        service, client = _service(tmp_path)
        identity = service.start(_campaign(), _invocation())
        container = client.containers.created[0][3]
        container.attrs["Config"]["Labels"]["com.bigeye.image-id"] = "sha256:swapped"

        with pytest.raises(Exception, match="contract"):
            service.stop(identity)

        assert not any(call[0] in {"stop", "kill", "remove"} for call in container.calls[2:])
