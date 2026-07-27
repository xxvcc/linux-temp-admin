#!/usr/bin/python3

import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


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
