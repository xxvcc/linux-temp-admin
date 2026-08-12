#!/usr/bin/python3

import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("mirror-receiver.py")
SPEC = importlib.util.spec_from_file_location("mirror_receiver", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
mirror_receiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mirror_receiver)


def make_version(
    parent: Path,
    tag: str = "v2.8.0",
    installer: bytes = b"#!/bin/sh\nexit 0\n",
) -> Path:
    parent.mkdir(mode=0o755)
    directory = parent / tag
    directory.mkdir(mode=0o755)
    payloads = {
        "linux-temp-admin-linux-amd64": b"amd64-binary",
        "linux-temp-admin-linux-amd64.sig": b"a" * 64,
        "linux-temp-admin-linux-arm64": b"arm64-binary",
        "linux-temp-admin-linux-arm64.sig": b"b" * 64,
        "install.sh": installer,
    }
    for name, content in payloads.items():
        (directory / name).write_bytes(content)
        (directory / name).chmod(0o644)
    (directory / "SHA256SUMS").write_bytes(mirror_receiver.canonical_checksum_bytes(directory))
    (directory / "SHA256SUMS").chmod(0o644)
    return directory


def make_latest(path: Path, tag: str, published_at: str = "2026-07-27T00:00:00Z") -> Path:
    path.write_text(
        json.dumps(
            {
                "version": tag[1:],
                "tag": tag,
                "base_url": f"https://dl.ll.cd/linux-temp-admin/{tag}",
                "published_at": published_at,
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    path.chmod(0o644)
    return path


class ParseRequestTests(unittest.TestCase):
    def test_accepts_only_expected_destinations(self) -> None:
        version = "rsync --server --ignore-existing -logDtprce.iLsfxCIvu --delay-updates . v2.8.0/"
        stable = "rsync --server -logDtprce.iLsfxCIvu --delay-updates . install.sh"
        self.assertEqual(mirror_receiver.parse_request(version), ("version", "v2.8.0"))
        self.assertEqual(mirror_receiver.parse_request(stable), ("stable", "install.sh"))

    def test_rejects_unsafe_or_mutable_version_commands(self) -> None:
        commands = (
            "bash -c id",
            "rsync --server -logDtpre.iLsfxCIvu . v2.8.0/",
            "rsync --server --ignore-existing --inplace . v2.8.0/",
            "rsync --server --ignore-existing --only-write-batch=/tmp/out . v2.8.0/",
            "rsync --server --ignore-existing --files-from=/tmp/list . v2.8.0/",
            "rsync --server --ignore-existing -D --delay-updates . v2.8.0/",
            "rsync --server --ignore-existing -Rb --delay-updates . v2.8.0/",
            "rsync --server --ignore-existing . ../v2.8.0/",
            "rsync --server --ignore-existing . v1.9.9/",
            "rsync --server --sender --ignore-existing . v2.8.0/",
            "rsync --server --ignore-existing . latest.json extra",
            "rsync --server --ignore-existing . 'v2.8.0/'",
            "rsync --server --ignore-existing . v2.8.0\\/",
            "rsync\t--server --ignore-existing . v2.8.0/",
            "rsync --server --ignore-existing --delay-updates . install.sh",
        )
        for command in commands:
            with self.subTest(command=command), self.assertRaises(mirror_receiver.ReceiverError):
                mirror_receiver.parse_request(command)

    def test_orders_maximum_length_components_without_integer_conversion(self) -> None:
        smaller = "v2." + "8" * 124 + ".0"
        larger = "v2." + "9" * 124 + ".0"
        self.assertEqual(len(smaller), mirror_receiver.MAX_RELEASE_TAG_BYTES)
        self.assertGreater(
            mirror_receiver.release_version_tuple(larger, stable=False),
            mirror_receiver.release_version_tuple(smaller, stable=False),
        )

    def test_rejects_release_tag_above_maximum_length(self) -> None:
        too_long = "v2." + "9" * 125 + ".0"
        self.assertEqual(len(too_long), mirror_receiver.MAX_RELEASE_TAG_BYTES + 1)
        with self.assertRaisesRegex(mirror_receiver.ReceiverError, "tag limit"):
            mirror_receiver.release_version_tuple(too_long, stable=False)
        command = (
            "rsync --server --ignore-existing -logDtprce.iLsfxCIvu "
            f"--delay-updates . {too_long}/"
        )
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.parse_request(command)


class TrustedExecutableTests(unittest.TestCase):
    def test_requires_canonical_owned_nonwritable_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mirror-executable-test-") as temporary:
            directory = Path(temporary)
            executable = directory / "rrsync"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            executable.chmod(0o755)
            mirror_receiver.require_trusted_executable(executable, owner=os.getuid())

            executable.chmod(0o775)
            with self.assertRaises(mirror_receiver.ReceiverError):
                mirror_receiver.require_trusted_executable(executable, owner=os.getuid())

            executable.chmod(0o644)
            with self.assertRaises(mirror_receiver.ReceiverError):
                mirror_receiver.require_trusted_executable(executable, owner=os.getuid())

            executable.chmod(0o755)
            symlink = directory / "rrsync-link"
            symlink.symlink_to(executable)
            with self.assertRaises(mirror_receiver.ReceiverError):
                mirror_receiver.require_trusted_executable(symlink, owner=os.getuid())


class StagingBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="mirror-budget-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary)

    def test_accepts_complete_release_tree(self) -> None:
        make_version(self.temporary / "stage")
        mirror_receiver.require_staging_budget(self.temporary / "stage")

    def test_residual_and_current_transfers_share_one_aggregate_budget(self) -> None:
        residual = self.temporary / "transfer-residual"
        current = self.temporary / "transfer-current"
        residual.mkdir()
        current.mkdir()
        residual_file = residual / "old"
        current_file = current / "new"
        residual_file.write_bytes(b"old")
        current_file.write_bytes(b"new")
        total_allocated = sum(
            max(path.stat().st_size, path.stat().st_blocks * 512)
            for path in (residual_file, current_file)
        )
        original = mirror_receiver.MAX_STAGING_BYTES
        try:
            mirror_receiver.MAX_STAGING_BYTES = total_allocated - 1
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "total-byte limit"
            ):
                mirror_receiver.require_staging_budget(self.temporary)
        finally:
            mirror_receiver.MAX_STAGING_BYTES = original

    def test_rejects_total_bytes_files_and_directory_entries(self) -> None:
        original = (
            mirror_receiver.MAX_STAGING_BYTES,
            mirror_receiver.MAX_STAGING_FILES,
            mirror_receiver.MAX_STAGING_ENTRIES,
        )
        try:
            byte_stage = self.temporary / "bytes"
            byte_stage.mkdir()
            (byte_stage / "large").write_bytes(b"12345")
            mirror_receiver.MAX_STAGING_BYTES = 4
            with self.assertRaisesRegex(mirror_receiver.ReceiverError, "total-byte limit"):
                mirror_receiver.require_staging_budget(byte_stage)

            file_stage = self.temporary / "files"
            file_stage.mkdir()
            (file_stage / "one").touch()
            (file_stage / "two").touch()
            mirror_receiver.MAX_STAGING_BYTES = original[0]
            mirror_receiver.MAX_STAGING_FILES = 1
            with self.assertRaisesRegex(mirror_receiver.ReceiverError, "file limit"):
                mirror_receiver.require_staging_budget(file_stage)

            entry_stage = self.temporary / "entries"
            entry_stage.mkdir()
            (entry_stage / "one").mkdir()
            (entry_stage / "two").mkdir()
            mirror_receiver.MAX_STAGING_FILES = original[1]
            mirror_receiver.MAX_STAGING_ENTRIES = 1
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "directory-entry limit"
            ):
                mirror_receiver.require_staging_budget(entry_stage)
        finally:
            (
                mirror_receiver.MAX_STAGING_BYTES,
                mirror_receiver.MAX_STAGING_FILES,
                mirror_receiver.MAX_STAGING_ENTRIES,
            ) = original

    def test_running_transfer_is_killed_as_soon_as_it_exceeds_budget(self) -> None:
        fake_rrsync = self.temporary / "rrsync"
        fake_rrsync.write_text(
            "#!/bin/sh\n"
            "stage=\n"
            "for argument do stage=$argument; done\n"
            "mkdir \"$stage/flood\"\n"
            ": > \"$stage/flood/one\"\n"
            ": > \"$stage/flood/two\"\n"
            "sleep 30\n",
            encoding="ascii",
        )
        fake_rrsync.chmod(0o755)
        stage = self.temporary / "running-stage"
        stage.mkdir()
        original = (
            mirror_receiver.RRSYNC,
            mirror_receiver.STAGING_SCAN_INTERVAL_SECONDS,
            mirror_receiver.TRANSFER_TIMEOUT_SECONDS,
            mirror_receiver.MAX_STAGING_ENTRIES,
        )
        try:
            mirror_receiver.RRSYNC = fake_rrsync
            mirror_receiver.STAGING_SCAN_INTERVAL_SECONDS = 0.01
            mirror_receiver.TRANSFER_TIMEOUT_SECONDS = 2
            mirror_receiver.MAX_STAGING_ENTRIES = 2
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "directory-entry limit"
            ):
                mirror_receiver.run_rrsync(stage, "accepted-test-command")
        finally:
            (
                mirror_receiver.RRSYNC,
                mirror_receiver.STAGING_SCAN_INTERVAL_SECONDS,
                mirror_receiver.TRANSFER_TIMEOUT_SECONDS,
                mirror_receiver.MAX_STAGING_ENTRIES,
            ) = original

    def test_nonreceiver_monitor_failure_kills_transfer_and_preserves_error(self) -> None:
        process = mock.Mock()
        process.returncode = None
        process.pid = 12345
        process.wait.side_effect = mirror_receiver.subprocess.TimeoutExpired(
            cmd="rrsync", timeout=0.01
        )
        primary = RuntimeError("monitor failed unexpectedly")
        stage = self.temporary / "monitor-failure-stage"
        stage.mkdir()
        with mock.patch.object(
            mirror_receiver.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            mirror_receiver, "require_staging_budget", side_effect=primary
        ), mock.patch.object(mirror_receiver, "kill_transfer") as kill:
            with self.assertRaises(RuntimeError) as caught:
                mirror_receiver.run_rrsync(stage, "accepted-test-command")
        self.assertIs(caught.exception, primary)
        kill.assert_called_once_with(process)

    def test_transfer_kill_failure_preserves_the_monitor_error(self) -> None:
        process = mock.Mock()
        process.returncode = None
        process.wait.side_effect = mirror_receiver.subprocess.TimeoutExpired(
            cmd="rrsync", timeout=0.01
        )
        primary = RuntimeError("monitor failed unexpectedly")
        cleanup = OSError("could not reap transfer group")
        stage = self.temporary / "kill-failure-stage"
        stage.mkdir()
        with mock.patch.object(
            mirror_receiver.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            mirror_receiver, "require_staging_budget", side_effect=primary
        ), mock.patch.object(
            mirror_receiver, "kill_transfer", side_effect=cleanup
        ):
            with self.assertRaises(RuntimeError) as caught:
                mirror_receiver.run_rrsync(stage, "accepted-test-command")
        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, cleanup)

    def test_nonblocking_deployment_lock_serializes_staging(self) -> None:
        lock = self.temporary / ".deploy.lock"
        first = mirror_receiver.open_lock(lock, owner=os.getuid(), nonblocking=True)
        try:
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "deployment is already active"
            ):
                mirror_receiver.open_lock(lock, owner=os.getuid(), nonblocking=True)
        finally:
            os.close(first)
        second = mirror_receiver.open_lock(lock, owner=os.getuid(), nonblocking=True)
        os.close(second)

    def test_staging_cleanup_failure_is_not_silently_ignored(self) -> None:
        stage = self.temporary / "transfer-cleanup-failure"
        stage.mkdir()
        with mock.patch.object(
            mirror_receiver.shutil,
            "rmtree",
            side_effect=PermissionError("cleanup denied"),
        ):
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "cannot remove rsync staging tree"
            ):
                mirror_receiver.remove_staging_tree(stage)

    def test_staging_cleanup_rechecks_residual_aggregate(self) -> None:
        residual = self.temporary / "transfer-residual"
        residual.mkdir()
        (residual / "one").touch()
        (residual / "two").touch()
        stage = self.temporary / "transfer-current"
        stage.mkdir()
        original = mirror_receiver.MAX_STAGING_FILES
        try:
            mirror_receiver.MAX_STAGING_FILES = 1
            with self.assertRaisesRegex(mirror_receiver.ReceiverError, "file limit"):
                mirror_receiver.remove_staging_tree(stage)
        finally:
            mirror_receiver.MAX_STAGING_FILES = original
        self.assertFalse(stage.exists())

    def test_cleanup_error_preserves_the_original_receiver_diagnostic(self) -> None:
        stage = self.temporary / "transfer-combined-error"
        stage.mkdir()
        primary = mirror_receiver.ReceiverError("publication failed first")
        cleanup = mirror_receiver.ReceiverError("cleanup failed second")
        with mock.patch.object(
            mirror_receiver,
            "remove_staging_tree",
            side_effect=cleanup,
        ):
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError,
                "publication failed first; additionally, cleanup failed second",
            ) as caught:
                mirror_receiver.finish_staging_tree(stage, primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, cleanup)

    def test_cleanup_error_preserves_a_nonreceiver_primary_exception(self) -> None:
        stage = self.temporary / "transfer-nonreceiver-error"
        stage.mkdir()
        primary = RuntimeError("unexpected publication failure")
        cleanup = mirror_receiver.ReceiverError("cleanup failed second")
        with mock.patch.object(
            mirror_receiver,
            "remove_staging_tree",
            side_effect=cleanup,
        ):
            with self.assertRaises(RuntimeError) as caught:
                mirror_receiver.finish_staging_tree(stage, primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, cleanup)


class ProjectBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="mirror-project-budget-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary)

    def test_rejects_project_bytes_entries_files_and_version_count(self) -> None:
        project = self.temporary / "project"
        make_version(project, tag="v2.8.0")
        originals = (
            mirror_receiver.MAX_PROJECT_BYTES,
            mirror_receiver.MAX_PROJECT_FILES,
            mirror_receiver.MAX_PROJECT_ENTRIES,
            mirror_receiver.MAX_PROJECT_VERSIONS,
        )
        try:
            mirror_receiver.MAX_PROJECT_BYTES = 1
            with self.assertRaisesRegex(mirror_receiver.ReceiverError, "total-byte limit"):
                mirror_receiver.require_project_budget(project)

            mirror_receiver.MAX_PROJECT_BYTES = originals[0]
            mirror_receiver.MAX_PROJECT_FILES = 1
            with self.assertRaisesRegex(mirror_receiver.ReceiverError, "file limit"):
                mirror_receiver.require_project_budget(project)

            mirror_receiver.MAX_PROJECT_FILES = originals[1]
            mirror_receiver.MAX_PROJECT_ENTRIES = 1
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "directory-entry limit"
            ):
                mirror_receiver.require_project_budget(project)

            mirror_receiver.MAX_PROJECT_ENTRIES = originals[2]
            mirror_receiver.MAX_PROJECT_VERSIONS = 0
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "release-version limit"
            ):
                mirror_receiver.require_project_budget(project)
        finally:
            (
                mirror_receiver.MAX_PROJECT_BYTES,
                mirror_receiver.MAX_PROJECT_FILES,
                mirror_receiver.MAX_PROJECT_ENTRIES,
                mirror_receiver.MAX_PROJECT_VERSIONS,
            ) = originals

    def test_rejects_overlong_release_directory_in_project_tree(self) -> None:
        project = self.temporary / "project"
        project.mkdir()
        overlong = "v2." + "9" * 125 + ".0"
        self.assertEqual(len(overlong), mirror_receiver.MAX_RELEASE_TAG_BYTES + 1)
        (project / overlong).mkdir()
        with self.assertRaisesRegex(
            mirror_receiver.ReceiverError, "overlong release-version directory"
        ):
            mirror_receiver.require_project_budget(project)

    def test_rejects_publication_before_available_space_reserve_is_crossed(self) -> None:
        project = self.temporary / "project"
        project.mkdir()
        filesystem = os.statvfs(project)
        fake = mock.Mock(
            f_blocks=filesystem.f_blocks,
            f_bavail=1,
            f_frsize=filesystem.f_frsize,
        )
        with mock.patch.object(mirror_receiver.os, "statvfs", return_value=fake):
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "available-byte reserve"
            ):
                mirror_receiver.require_project_budget(project, additional_bytes=1)

    def test_available_space_reserve_is_at_least_five_percent(self) -> None:
        project = self.temporary / "project"
        project.mkdir()
        block_size = 1024 * 1024
        original_minimum = mirror_receiver.MIN_PROJECT_AVAILABLE_BYTES
        try:
            mirror_receiver.MIN_PROJECT_AVAILABLE_BYTES = 0
            below_reserve = mock.Mock(
                f_blocks=1000,
                f_bavail=49,
                f_frsize=block_size,
            )
            with mock.patch.object(
                mirror_receiver.os, "statvfs", return_value=below_reserve
            ):
                with self.assertRaisesRegex(
                    mirror_receiver.ReceiverError,
                    f"available-byte reserve of {50 * block_size}",
                ):
                    mirror_receiver.require_project_budget(project)

            exact_reserve = mock.Mock(
                f_blocks=1000,
                f_bavail=50,
                f_frsize=block_size,
            )
            with mock.patch.object(
                mirror_receiver.os, "statvfs", return_value=exact_reserve
            ):
                mirror_receiver.require_project_budget(project)
                with self.assertRaisesRegex(
                    mirror_receiver.ReceiverError, "available-byte reserve"
                ):
                    mirror_receiver.require_project_budget(
                        project, additional_bytes=1
                    )
        finally:
            mirror_receiver.MIN_PROJECT_AVAILABLE_BYTES = original_minimum

    def test_new_version_preflight_counts_staged_growth(self) -> None:
        project = self.temporary / "project"
        project.mkdir()
        staged = make_version(self.temporary / "staged", tag="v2.9.5")
        original = mirror_receiver.MAX_PROJECT_BYTES
        try:
            mirror_receiver.MAX_PROJECT_BYTES = 1
            with self.assertRaisesRegex(mirror_receiver.ReceiverError, "total-byte limit"):
                mirror_receiver.publish_version(
                    staged, project / "v2.9.5", owner=os.getuid()
                )
        finally:
            mirror_receiver.MAX_PROJECT_BYTES = original
        self.assertFalse((project / "v2.9.5").exists())


class ReceiverPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="mirror-receiver-test-"))
        self.owner = os.getuid()
        self.project = self.temporary / "project"
        self.project.mkdir(mode=0o755)

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary)

    def test_version_is_create_only_idempotent_and_repairable(self) -> None:
        first = make_version(self.temporary / "first")
        destination = self.project / "v2.8.0"
        mirror_receiver.publish_version(first, destination, owner=self.owner)
        mirror_receiver.validate_version(destination, owner=self.owner, published=True)

        (destination / "linux-temp-admin-linux-arm64.sig").unlink()
        second = make_version(self.temporary / "second")
        mirror_receiver.publish_version(second, destination, owner=self.owner)
        mirror_receiver.validate_version(destination, owner=self.owner, published=True)

        third = make_version(self.temporary / "third")
        (third / "linux-temp-admin-linux-amd64").write_bytes(b"different")
        (third / "SHA256SUMS").write_bytes(mirror_receiver.canonical_checksum_bytes(third))
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.publish_version(third, destination, owner=self.owner)
        self.assertEqual(
            (destination / "linux-temp-admin-linux-amd64").read_bytes(), b"amd64-binary"
        )

    def test_version_recovers_interrupted_private_commit_states(self) -> None:
        staged = make_version(self.temporary / "interrupted")
        destination = self.project / "v2.8.0"
        destination.mkdir(mode=0o755)

        partial = destination / (
            ".mirror-linux-temp-admin-linux-amd64-" + "0" * 32
        )
        partial.write_bytes(b"partial")
        partial.chmod(0o600)

        linked = destination / (
            ".mirror-linux-temp-admin-linux-arm64.sig-" + "1" * 32
        )
        linked.write_bytes((staged / "linux-temp-admin-linux-arm64.sig").read_bytes())
        linked.chmod(0o644)
        os.link(linked, destination / "linux-temp-admin-linux-arm64.sig")
        self.assertEqual(linked.stat().st_nlink, 2)

        mirror_receiver.publish_version(staged, destination, owner=self.owner)

        mirror_receiver.validate_version(destination, owner=self.owner, published=True)
        self.assertFalse(
            any(entry.name.startswith(".mirror-") for entry in os.scandir(destination))
        )
        self.assertEqual((destination / "linux-temp-admin-linux-arm64.sig").stat().st_nlink, 1)

    def test_no_replace_commit_never_overwrites_existing_bytes(self) -> None:
        source = self.temporary / "no-replace-source"
        destination = self.temporary / "no-replace-destination"
        source.write_bytes(b"new")
        destination.write_bytes(b"existing")

        with self.assertRaisesRegex(
            mirror_receiver.ReceiverError, "appeared concurrently"
        ):
            mirror_receiver.rename_noreplace(source, destination)

        self.assertEqual(destination.read_bytes(), b"existing")
        self.assertEqual(source.read_bytes(), b"new")

    def test_no_replace_fails_closed_when_primitive_is_unavailable(self) -> None:
        source = self.temporary / "unsupported-source"
        destination = self.temporary / "unsupported-destination"
        source.write_bytes(b"source")
        original_renameat2 = mirror_receiver.RENAMEAT2
        try:
            mirror_receiver.RENAMEAT2 = None
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "is unavailable"
            ):
                mirror_receiver.rename_noreplace(source, destination)

            class UnsupportedRename:
                def __call__(self, *args) -> int:
                    mirror_receiver.ctypes.set_errno(mirror_receiver.errno.EOPNOTSUPP)
                    return -1

            mirror_receiver.RENAMEAT2 = UnsupportedRename()
            with self.assertRaisesRegex(
                mirror_receiver.ReceiverError, "cannot atomically publish"
            ):
                mirror_receiver.rename_noreplace(source, destination)
        finally:
            mirror_receiver.RENAMEAT2 = original_renameat2

        self.assertEqual(source.read_bytes(), b"source")
        self.assertFalse(destination.exists())

    def test_version_retry_after_commit_before_directory_sync(self) -> None:
        staged = make_version(self.temporary / "sync-interruption")
        destination = self.project / "v2.8.0"
        original_fsync_directory = mirror_receiver.fsync_directory
        interrupted = False

        def fail_first_version_sync(path: Path) -> None:
            nonlocal interrupted
            if path == destination and not interrupted:
                interrupted = True
                raise OSError("simulated interruption after no-replace commit")
            original_fsync_directory(path)

        mirror_receiver.fsync_directory = fail_first_version_sync
        try:
            with self.assertRaisesRegex(OSError, "simulated interruption"):
                mirror_receiver.publish_version(staged, destination, owner=self.owner)
        finally:
            mirror_receiver.fsync_directory = original_fsync_directory

        self.assertTrue(interrupted)
        self.assertFalse(
            any(entry.name.startswith(".mirror-") for entry in os.scandir(destination))
        )
        mirror_receiver.publish_version(staged, destination, owner=self.owner)
        mirror_receiver.validate_version(destination, owner=self.owner, published=True)

    def test_version_rejects_unsafe_stale_private_temp(self) -> None:
        staged = make_version(self.temporary / "unsafe-private-temp")
        destination = self.project / "v2.8.0"
        destination.mkdir(mode=0o755)
        temporary = destination / (
            ".mirror-linux-temp-admin-linux-amd64-" + "2" * 32
        )
        temporary.symlink_to(staged / "linux-temp-admin-linux-amd64")

        with self.assertRaisesRegex(
            mirror_receiver.ReceiverError, "unsafe stale mirror temporary file"
        ):
            mirror_receiver.publish_version(staged, destination, owner=self.owner)
        self.assertTrue(temporary.is_symlink())

    def test_version_rejects_unexpected_private_temp_hardlinks(self) -> None:
        staged = make_version(self.temporary / "unsafe-hardlinks")

        wrong_target = self.project / "v2.8.0"
        wrong_target.mkdir(mode=0o755)
        linked_elsewhere = wrong_target / (
            ".mirror-linux-temp-admin-linux-amd64-" + "4" * 32
        )
        linked_elsewhere.write_bytes(b"partial")
        linked_elsewhere.chmod(0o644)
        outside = self.temporary / "unexpected-link"
        os.link(linked_elsewhere, outside)
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.publish_version(staged, wrong_target, owner=self.owner)
        self.assertTrue(linked_elsewhere.exists())
        self.assertTrue(outside.exists())

        too_many = self.project / "v2.8.1"
        too_many.mkdir(mode=0o755)
        private = too_many / (".mirror-SHA256SUMS-" + "5" * 32)
        private.write_bytes(b"partial")
        private.chmod(0o644)
        os.link(private, too_many / "SHA256SUMS")
        third = self.temporary / "third-link"
        os.link(private, third)
        with self.assertRaisesRegex(
            mirror_receiver.ReceiverError, "unsafe stale mirror temporary file"
        ):
            mirror_receiver.publish_version(staged, too_many, owner=self.owner)
        self.assertEqual(private.stat().st_nlink, 3)

    def test_new_version_directory_ignores_restrictive_process_umask(self) -> None:
        staged = make_version(self.temporary / "restrictive-umask")
        destination = self.project / "v2.8.0"
        previous_umask = os.umask(0o077)
        try:
            mirror_receiver.publish_version(staged, destination, owner=self.owner)
        finally:
            os.umask(previous_umask)

        self.assertEqual(destination.stat().st_mode & 0o7777, 0o755)
        mirror_receiver.validate_version(destination, owner=self.owner, published=True)

    def test_version_retry_after_crash_immediately_after_directory_creation(self) -> None:
        staged = make_version(self.temporary / "mkdir-interruption")
        destination = self.project / "v2.8.0"
        child = os.fork()
        if child == 0:
            try:
                original_require_directory = mirror_receiver.require_directory

                def stop_after_mkdir(
                    path: Path, *, owner: int, mode: int | None = None
                ) -> None:
                    if path == destination:
                        os._exit(93)
                    original_require_directory(path, owner=owner, mode=mode)

                mirror_receiver.require_directory = stop_after_mkdir
                os.umask(0o077)
                mirror_receiver.publish_version(staged, destination, owner=self.owner)
            except BaseException:
                os._exit(95)
            os._exit(94)

        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 93)
        self.assertEqual(destination.stat().st_mode & 0o7777, 0o755)
        self.assertEqual(list(destination.iterdir()), [])

        synced = []
        original_fsync_directory = mirror_receiver.fsync_directory

        def record_directory_sync(path: Path) -> None:
            synced.append(path)
            original_fsync_directory(path)

        mirror_receiver.fsync_directory = record_directory_sync
        try:
            mirror_receiver.publish_version(staged, destination, owner=self.owner)
        finally:
            mirror_receiver.fsync_directory = original_fsync_directory
        self.assertIn(self.project, synced)
        mirror_receiver.validate_version(destination, owner=self.owner, published=True)

    def test_version_retry_after_crash_during_private_copy_with_extreme_umask(self) -> None:
        staged = make_version(self.temporary / "copy-interruption")
        destination = self.project / "v2.8.0"
        destination.mkdir(mode=0o755)
        child = os.fork()
        if child == 0:
            try:
                mirror_receiver.secrets.token_hex = lambda size: "3" * (size * 2)

                def stop_during_copy(source, target, length=0) -> None:
                    target.write(b"partial")
                    target.flush()
                    os._exit(93)

                mirror_receiver.shutil.copyfileobj = stop_during_copy
                os.umask(0o777)
                mirror_receiver.copy_to_private_temp(
                    staged / "SHA256SUMS", destination, "SHA256SUMS"
                )
            except BaseException:
                os._exit(95)
            os._exit(94)

        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 93)
        temporary = destination / (".mirror-SHA256SUMS-" + "3" * 32)
        self.assertEqual(temporary.stat().st_mode & 0o7777, 0o600)

        mirror_receiver.publish_version(staged, destination, owner=self.owner)
        mirror_receiver.validate_version(destination, owner=self.owner, published=True)

    def test_deployment_lock_creation_ignores_extreme_umask(self) -> None:
        lock = self.temporary / ".deploy.lock"
        previous_umask = os.umask(0o777)
        try:
            descriptor = mirror_receiver.open_lock(lock, owner=self.owner)
        finally:
            os.umask(previous_umask)
        os.close(descriptor)

        self.assertEqual(lock.stat().st_mode & 0o7777, 0o600)
        descriptor = mirror_receiver.open_lock(lock, owner=self.owner)
        os.close(descriptor)

    def test_version_rejects_extra_paths_and_bad_checksums(self) -> None:
        extra = make_version(self.temporary / "extra")
        (extra / "unexpected").write_text("no", encoding="ascii")
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.validate_version(extra, owner=self.owner)

        bad = make_version(self.temporary / "bad")
        (bad / "SHA256SUMS").write_text(
            "0" * 64 + "  linux-temp-admin-linux-amd64\n", encoding="ascii"
        )
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.validate_version(bad, owner=self.owner)

    def test_stable_files_must_bind_to_a_complete_version(self) -> None:
        staged_version = make_version(self.temporary / "version")
        mirror_receiver.publish_version(staged_version, self.project / "v2.8.0", owner=self.owner)

        staged_installer = self.temporary / "install.sh"
        staged_installer.write_bytes((self.project / "v2.8.0/install.sh").read_bytes())
        staged_installer.chmod(0o644)
        mirror_receiver.publish_stable(
            staged_installer, "install.sh", project_root=self.project, owner=self.owner
        )

        latest = make_latest(self.temporary / "latest.json", "v2.8.0")
        mirror_receiver.publish_stable(
            latest, "latest.json", project_root=self.project, owner=self.owner
        )
        self.assertEqual((self.project / "latest.json").read_bytes(), latest.read_bytes())

        wrong = self.temporary / "wrong-install.sh"
        wrong.write_bytes(b"#!/bin/sh\nexit 1\n")
        wrong.chmod(0o644)
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.publish_stable(
                wrong, "install.sh", project_root=self.project, owner=self.owner
            )

    def test_stable_publication_recovers_private_temporaries(self) -> None:
        staged_version = make_version(self.temporary / "stable-recovery")
        mirror_receiver.publish_version(
            staged_version, self.project / "v2.8.0", owner=self.owner
        )

        installer_temp = self.project / (".mirror-install.sh-" + "6" * 32)
        installer_temp.write_bytes(b"partial")
        installer_temp.chmod(0o600)
        mirror_receiver.publish_stable(
            staged_version / "install.sh",
            "install.sh",
            project_root=self.project,
            owner=self.owner,
        )
        self.assertFalse(installer_temp.exists())

        latest_temp = self.project / (".mirror-latest.json-" + "7" * 32)
        latest_temp.write_bytes(b"partial")
        latest_temp.chmod(0o600)
        latest = make_latest(self.temporary / "stable-recovery.json", "v2.8.0")
        mirror_receiver.publish_stable(
            latest, "latest.json", project_root=self.project, owner=self.owner
        )
        self.assertFalse(latest_temp.exists())
        self.assertEqual((self.project / "latest.json").read_bytes(), latest.read_bytes())

    def test_latest_rejects_noncanonical_or_inconsistent_content(self) -> None:
        staged_version = make_version(self.temporary / "version")
        mirror_receiver.publish_version(staged_version, self.project / "v2.8.0", owner=self.owner)
        shutil.copyfile(self.project / "v2.8.0/install.sh", self.project / "install.sh")
        (self.project / "install.sh").chmod(0o644)

        latest = self.temporary / "latest.json"
        latest.write_text(
            '{"tag":"v2.8.0","version":"2.8.0",'
            '"base_url":"https://dl.ll.cd/linux-temp-admin/v2.8.0",'
            '"published_at":"2026-07-27T00:00:00Z"}\n',
            encoding="ascii",
        )
        latest.chmod(0o644)
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.validate_latest(latest, owner=self.owner, project_root=self.project)

    def test_stable_metadata_rejects_prereleases(self) -> None:
        staged_version = make_version(self.temporary / "prerelease", tag="v2.9.0-rc.1")
        mirror_receiver.publish_version(
            staged_version, self.project / "v2.9.0-rc.1", owner=self.owner
        )
        shutil.copyfile(staged_version / "install.sh", self.project / "install.sh")
        (self.project / "install.sh").chmod(0o644)
        latest = make_latest(self.temporary / "prerelease-latest.json", "v2.9.0-rc.1")
        with self.assertRaises(mirror_receiver.ReceiverError):
            mirror_receiver.validate_latest(latest, owner=self.owner, project_root=self.project)

    def test_release_and_stable_metadata_reject_versions_below_v2(self) -> None:
        staged_version = make_version(self.temporary / "v1-version", tag="v1.9.9")
        with self.assertRaisesRegex(mirror_receiver.ReceiverError, "below v2"):
            mirror_receiver.publish_version(
                staged_version, self.project / "v1.9.9", owner=self.owner
            )

        published_version = self.project / "v1.9.9"
        shutil.copytree(staged_version, published_version)
        published_version.chmod(0o755)
        staged_installer = self.temporary / "v1-install.sh"
        shutil.copyfile(staged_version / "install.sh", staged_installer)
        staged_installer.chmod(0o644)
        with self.assertRaisesRegex(
            mirror_receiver.ReceiverError, "not byte-identical to a complete stable version"
        ):
            mirror_receiver.publish_stable(
                staged_installer, "install.sh", project_root=self.project, owner=self.owner
            )

        latest = make_latest(self.temporary / "v1-latest.json", "v1.9.9")
        with self.assertRaisesRegex(mirror_receiver.ReceiverError, "below v2"):
            mirror_receiver.validate_latest(latest, owner=self.owner, project_root=self.project)

    def test_stable_files_cannot_roll_back_or_mutate_current_metadata(self) -> None:
        old = make_version(
            self.temporary / "old-version", tag="v2.8.0", installer=b"#!/bin/sh\n# old\n"
        )
        new = make_version(
            self.temporary / "new-version", tag="v2.9.0", installer=b"#!/bin/sh\n# new\n"
        )
        mirror_receiver.publish_version(old, self.project / "v2.8.0", owner=self.owner)
        mirror_receiver.publish_version(new, self.project / "v2.9.0", owner=self.owner)

        old_installer = self.temporary / "old-install.sh"
        shutil.copyfile(old / "install.sh", old_installer)
        old_installer.chmod(0o644)
        mirror_receiver.publish_stable(
            old_installer, "install.sh", project_root=self.project, owner=self.owner
        )
        old_latest = make_latest(self.temporary / "old-latest.json", "v2.8.0")
        mirror_receiver.publish_stable(
            old_latest, "latest.json", project_root=self.project, owner=self.owner
        )

        new_installer = self.temporary / "new-install.sh"
        shutil.copyfile(new / "install.sh", new_installer)
        new_installer.chmod(0o644)
        mirror_receiver.publish_stable(
            new_installer, "install.sh", project_root=self.project, owner=self.owner
        )
        new_latest = make_latest(self.temporary / "new-latest.json", "v2.9.0")
        mirror_receiver.publish_stable(
            new_latest, "latest.json", project_root=self.project, owner=self.owner
        )

        with self.assertRaisesRegex(mirror_receiver.ReceiverError, "roll back"):
            mirror_receiver.publish_stable(
                old_installer, "install.sh", project_root=self.project, owner=self.owner
            )

        shutil.copyfile(old / "install.sh", self.project / "install.sh")
        (self.project / "install.sh").chmod(0o644)
        with self.assertRaisesRegex(mirror_receiver.ReceiverError, "roll back"):
            mirror_receiver.publish_stable(
                old_latest, "latest.json", project_root=self.project, owner=self.owner
            )
        self.assertEqual((self.project / "latest.json").read_bytes(), new_latest.read_bytes())

        shutil.copyfile(new / "install.sh", self.project / "install.sh")
        (self.project / "install.sh").chmod(0o644)
        changed_latest = make_latest(
            self.temporary / "changed-latest.json",
            "v2.9.0",
            published_at="2026-07-27T00:00:01Z",
        )
        with self.assertRaisesRegex(mirror_receiver.ReceiverError, "cannot mutate"):
            mirror_receiver.publish_stable(
                changed_latest, "latest.json", project_root=self.project, owner=self.owner
            )


if __name__ == "__main__":
    unittest.main()
