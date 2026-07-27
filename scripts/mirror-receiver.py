#!/usr/bin/python3
"""Restricted rsync receiver for the official linux-temp-admin mirror."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile


PROJECT_ROOT = Path("/www/wwwroot/dl.ll.cd/linux-temp-admin")
INCOMING_ROOT = Path("/var/lib/linux-temp-admin-mirror")
LOCK_PATH = INCOMING_ROOT / ".deploy.lock"
RRSYNC = Path("/usr/bin/rrsync")
MIRROR_BASE_URL = "https://dl.ll.cd/linux-temp-admin"
TRANSFER_TIMEOUT_SECONDS = 300
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024

VERSION_PATTERN = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?"
)
EXPECTED_VERSION_FILES = (
    "SHA256SUMS",
    "linux-temp-admin-linux-amd64",
    "linux-temp-admin-linux-amd64.sig",
    "linux-temp-admin-linux-arm64",
    "linux-temp-admin-linux-arm64.sig",
    "install.sh",
)
CHECKSUM_FILES = (
    "linux-temp-admin-linux-amd64",
    "linux-temp-admin-linux-amd64.sig",
    "linux-temp-admin-linux-arm64",
    "linux-temp-admin-linux-arm64.sig",
)
STABLE_FILES = ("install.sh", "latest.json")


class ReceiverError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReceiverError(message)


def lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {path}: {exc}")


def require_directory(path: Path, *, owner: int, mode: int | None = None) -> None:
    info = lstat(path)
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        fail(f"not a real directory: {path}")
    if info.st_uid != owner:
        fail(f"unexpected directory owner: {path}")
    if info.st_mode & 0o7022:
        fail(f"directory is writable by another account or has special bits: {path}")
    if mode is not None and stat.S_IMODE(info.st_mode) != mode:
        fail(f"unexpected directory mode: {path}")


def require_safe_ancestry(path: Path, *, leaf_owner: int, leaf_mode: int) -> None:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        fail(f"path is not canonical: {path}")
    current = Path("/")
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        info = lstat(current)
        if not stat.S_ISDIR(info.st_mode) or current.is_symlink():
            fail(f"unsafe directory ancestor: {current}")
        is_leaf = index == len(parts) - 1
        expected_owner = leaf_owner if is_leaf else 0
        if info.st_uid != expected_owner:
            fail(f"unexpected directory owner: {current}")
        if info.st_mode & 0o7022:
            fail(f"unsafe directory permissions: {current}")
        if is_leaf and stat.S_IMODE(info.st_mode) != leaf_mode:
            fail(f"unexpected directory mode: {current}")


def require_regular(path: Path, *, owner: int, maximum: int, exact: int | None = None) -> int:
    info = lstat(path)
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        fail(f"not a regular file: {path}")
    if info.st_uid != owner or info.st_nlink != 1:
        fail(f"unsafe file ownership or link count: {path}")
    if info.st_mode & 0o7022:
        fail(f"file is writable by another account or has special bits: {path}")
    if info.st_size <= 0 or info.st_size > maximum:
        fail(f"file has an invalid size: {path}")
    if exact is not None and info.st_size != exact:
        fail(f"file has an unexpected exact size: {path}")
    return info.st_size


def require_trusted_executable(path: Path, *, owner: int) -> None:
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        fail(f"cannot resolve trusted executable {path}: {exc}")
    if not path.is_absolute() or canonical != path:
        fail(f"trusted executable path is not canonical: {path}")
    info = lstat(path)
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        fail(f"trusted executable is not a regular file: {path}")
    if info.st_uid != owner or info.st_mode & 0o7022:
        fail(f"trusted executable has unsafe ownership or permissions: {path}")
    if info.st_size <= 0 or info.st_size > MAX_METADATA_BYTES:
        fail(f"trusted executable has an invalid size: {path}")
    if stat.S_IMODE(info.st_mode) & 0o111 == 0 or not os.access(path, os.X_OK):
        fail(f"trusted executable is not executable: {path}")


def parse_request(command: str) -> tuple[str, str]:
    if not command or "\x00" in command or "\n" in command or "\r" in command:
        fail("missing or malformed SSH_ORIGINAL_COMMAND")
    if any(character in "'\"\\" or ord(character) < 0x20 or ord(character) == 0x7F
           for character in command):
        fail("SSH_ORIGINAL_COMMAND contains ambiguous quoting or control characters")
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        fail(f"invalid rsync command quoting: {exc}")
    if len(argv) < 5 or argv[:2] != ["rsync", "--server"] or "--sender" in argv:
        fail("only an rsync receiver command is allowed")
    dot_indexes = [index for index, value in enumerate(argv) if value == "."]
    if len(dot_indexes) != 1:
        fail("rsync command must contain one destination marker")
    dot_index = dot_indexes[0]
    if dot_index < 3 or len(argv[dot_index + 1 :]) != 1:
        fail("rsync command must contain one destination")
    destination = argv[dot_index + 1]
    if destination.startswith("./"):
        destination = destination[2:]
    options = argv[2:dot_index]
    if destination in STABLE_FILES:
        request_type = "stable"
        normalized_destination = destination
        expected_long_options = ["--delay-updates"]
    else:
        version = destination[:-1] if destination.endswith("/") else destination
        version_match = VERSION_PATTERN.fullmatch(version)
        if version_match is None:
            fail("destination is not an allowed stable file or canonical version directory")
        major = version_match.group(1)
        if len(major) == 1 and int(major) < 2:
            fail("release versions below v2 are not accepted")
        if destination != f"{version}/":
            fail("version uploads must be directory-scoped")
        request_type = "version"
        normalized_destination = version
        expected_long_options = ["--delay-updates", "--ignore-existing"]

    short_options = [option for option in options if not option.startswith("--")]
    long_options = [option for option in options if option.startswith("--")]
    if (
        short_options != ["-logDtprce.iLsfxCIvu"]
        or sorted(long_options) != sorted(expected_long_options)
    ):
        fail("rsync command does not use the exact deployment option profile")
    return request_type, normalized_destination


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def files_equal(left: Path, right: Path) -> bool:
    left_info = lstat(left)
    right_info = lstat(right)
    if not stat.S_ISREG(left_info.st_mode) or not stat.S_ISREG(right_info.st_mode):
        return False
    if left_info.st_size != right_info.st_size:
        return False
    with left.open("rb", buffering=0) as left_handle, right.open("rb", buffering=0) as right_handle:
        while True:
            left_chunk = left_handle.read(1024 * 1024)
            right_chunk = right_handle.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def canonical_checksum_bytes(directory: Path) -> bytes:
    return b"".join(
        f"{sha256_file(directory / name)}  {name}\n".encode("ascii")
        for name in CHECKSUM_FILES
    )


def validate_version(directory: Path, *, owner: int, published: bool = False) -> None:
    require_directory(directory, owner=owner, mode=0o755 if published else None)
    entries = sorted(entry.name for entry in os.scandir(directory))
    if entries != sorted(EXPECTED_VERSION_FILES):
        fail(f"version directory does not contain the exact release set: {directory}")
    for name in EXPECTED_VERSION_FILES:
        maximum = MAX_BINARY_BYTES if name in (
            "linux-temp-admin-linux-amd64",
            "linux-temp-admin-linux-arm64",
        ) else MAX_METADATA_BYTES
        exact = 64 if name.endswith(".sig") else None
        require_regular(directory / name, owner=owner, maximum=maximum, exact=exact)
    checksum = (directory / "SHA256SUMS").read_bytes()
    if checksum != canonical_checksum_bytes(directory):
        fail(f"SHA256SUMS is not canonical or does not match the release files: {directory}")
    if published:
        for name in EXPECTED_VERSION_FILES:
            if stat.S_IMODE(lstat(directory / name).st_mode) != 0o644:
                fail(f"published release file mode is not 0644: {directory / name}")


def stable_version_tuple(tag: str) -> tuple[int, int, int]:
    match = VERSION_PATTERN.fullmatch(tag)
    if match is None or match.group(4) is not None:
        fail("stable metadata must name a canonical non-prerelease tag")
    return tuple(int(match.group(index)) for index in range(1, 4))


def parse_latest(path: Path, *, owner: int) -> tuple[dict[str, str], bytes]:
    require_regular(path, owner=owner, maximum=MAX_METADATA_BYTES)
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"latest.json is not canonical ASCII JSON: {exc}")
    if not isinstance(value, dict) or list(value) != ["version", "tag", "base_url", "published_at"]:
        fail("latest.json has an unexpected field set or order")
    if not all(isinstance(item, str) for item in value.values()):
        fail("latest.json fields must all be strings")
    tag = value["tag"]
    stable_version_tuple(tag)
    if value["version"] != tag[1:]:
        fail("latest.json has an invalid tag/version pair")
    if value["base_url"] != f"{MIRROR_BASE_URL}/{tag}":
        fail("latest.json has an invalid base_url")
    published_at = value["published_at"]
    if re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
        published_at,
    ) is None:
        fail("latest.json has an invalid published_at")
    try:
        dt.datetime.fromisoformat(published_at[:-1] + "+00:00")
    except ValueError as exc:
        fail(f"latest.json has an invalid timestamp: {exc}")
    canonical = (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    if raw != canonical:
        fail("latest.json is not canonical single-line JSON")
    return value, raw


def validate_latest(path: Path, *, owner: int, project_root: Path) -> dict[str, str]:
    value, _ = parse_latest(path, owner=owner)
    tag = value["tag"]
    version_dir = project_root / tag
    validate_version(version_dir, owner=owner, published=True)
    stable_installer = project_root / "install.sh"
    require_regular(stable_installer, owner=owner, maximum=MAX_METADATA_BYTES)
    if not files_equal(stable_installer, version_dir / "install.sh"):
        fail("stable installer does not match the manifest version")
    return value


def current_latest_state(
    project_root: Path, *, owner: int
) -> tuple[tuple[int, int, int], bytes] | None:
    latest = project_root / "latest.json"
    if not latest.exists() and not latest.is_symlink():
        return None
    value, raw = parse_latest(latest, owner=owner)
    validate_version(project_root / value["tag"], owner=owner, published=True)
    return stable_version_tuple(value["tag"]), raw


def fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def copy_to_private_temp(source: Path, directory: Path, label: str) -> Path:
    temporary = directory / f".mirror-{label}-{secrets.token_hex(16)}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with source.open("rb", buffering=0) as source_handle, os.fdopen(
            descriptor, "wb", buffering=0, closefd=False
        ) as destination_handle:
            shutil.copyfileobj(source_handle, destination_handle, 1024 * 1024)
            os.fsync(destination_handle.fileno())
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)
    return temporary


def publish_version(staged: Path, destination: Path, *, owner: int) -> None:
    validate_version(staged, owner=owner)
    for name in EXPECTED_VERSION_FILES:
        os.chmod(staged / name, 0o644, follow_symlinks=False)
        fsync_file(staged / name)
    if destination.exists() or destination.is_symlink():
        require_directory(destination, owner=owner, mode=0o755)
        existing = sorted(entry.name for entry in os.scandir(destination))
        if not set(existing).issubset(EXPECTED_VERSION_FILES):
            fail(f"version directory contains a non-release path: {destination}")
        for name in existing:
            maximum = MAX_BINARY_BYTES if name in (
                "linux-temp-admin-linux-amd64",
                "linux-temp-admin-linux-arm64",
            ) else MAX_METADATA_BYTES
            exact = 64 if name.endswith(".sig") else None
            require_regular(destination / name, owner=owner, maximum=maximum, exact=exact)
            if stat.S_IMODE(lstat(destination / name).st_mode) != 0o644:
                fail(f"published release file mode is not 0644: {destination / name}")
            if not files_equal(staged / name, destination / name):
                fail(
                    "immutable release file already exists with different bytes: "
                    f"{destination / name}"
                )
    else:
        try:
            os.mkdir(destination, 0o755)
        except FileExistsError:
            fail(f"version destination appeared concurrently: {destination}")
        os.chmod(destination, 0o755, follow_symlinks=False)
        require_directory(destination, owner=owner, mode=0o755)
        fsync_directory(destination.parent)
    try:
        for name in EXPECTED_VERSION_FILES:
            if (destination / name).exists() or (destination / name).is_symlink():
                continue
            temporary = copy_to_private_temp(staged / name, destination, name)
            try:
                os.link(temporary, destination / name, follow_symlinks=False)
                temporary.unlink()
                fsync_directory(destination)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        validate_version(destination, owner=owner, published=True)
    except BaseException:
        # Valid files already linked into an incomplete version are deliberately
        # retained. A retry may fill the missing files but can never replace one.
        raise
    fsync_directory(destination)


def matching_stable_installer_versions(
    project_root: Path, installer: Path, *, owner: int
) -> list[tuple[int, int, int]]:
    matches: list[tuple[int, int, int]] = []
    with os.scandir(project_root) as entries:
        for entry in entries:
            version_match = VERSION_PATTERN.fullmatch(entry.name)
            if (not entry.is_dir(follow_symlinks=False) or version_match is None
                    or version_match.group(4) is not None):
                continue
            version_dir = project_root / entry.name
            try:
                validate_version(version_dir, owner=owner, published=True)
            except ReceiverError:
                continue
            if files_equal(installer, version_dir / "install.sh"):
                matches.append(tuple(int(version_match.group(index)) for index in range(1, 4)))
    return matches


def atomic_replace(staged: Path, destination: Path, *, project_root: Path, owner: int) -> None:
    require_regular(staged, owner=owner, maximum=MAX_METADATA_BYTES)
    os.chmod(staged, 0o644, follow_symlinks=False)
    fsync_file(staged)
    if destination.exists() or destination.is_symlink():
        require_regular(destination, owner=owner, maximum=MAX_METADATA_BYTES)
    temporary = copy_to_private_temp(staged, project_root, destination.name)
    try:
        os.replace(temporary, destination)
        fsync_directory(project_root)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def publish_stable(staged: Path, name: str, *, project_root: Path, owner: int) -> None:
    if name == "install.sh":
        require_regular(staged, owner=owner, maximum=MAX_METADATA_BYTES)
        matching_versions = matching_stable_installer_versions(
            project_root, staged, owner=owner
        )
        if not matching_versions:
            fail("stable installer is not byte-identical to a complete stable version")
        current = current_latest_state(project_root, owner=owner)
        if current is not None and not any(version >= current[0] for version in matching_versions):
            fail("stable installer would roll back the published stable version")
    elif name == "latest.json":
        candidate = validate_latest(staged, owner=owner, project_root=project_root)
        candidate_version = stable_version_tuple(candidate["tag"])
        candidate_raw = staged.read_bytes()
        current = current_latest_state(project_root, owner=owner)
        if current is not None:
            current_version, current_raw = current
            if candidate_version < current_version:
                fail("latest.json would roll back the published stable version")
            if candidate_version == current_version and candidate_raw != current_raw:
                fail("latest.json cannot mutate metadata for the current stable version")
    else:
        fail("unexpected stable file")
    atomic_replace(staged, project_root / name, project_root=project_root, owner=owner)


def limit_receiver() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BINARY_BYTES, MAX_BINARY_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def run_rrsync(stage: Path, original_command: str) -> None:
    environment = {
        "HOME": str(INCOMING_ROOT),
        "LC_ALL": "C",
        "LOGNAME": str(os.getuid()),
        "PATH": "/usr/bin:/bin",
        "SSH_CONNECTION": os.environ.get("SSH_CONNECTION", "unknown 0 unknown 0"),
        "SSH_ORIGINAL_COMMAND": original_command,
        "USER": str(os.getuid()),
    }
    process = subprocess.Popen(
        [str(RRSYNC), "-wo", "-no-del", str(stage)],
        env=environment,
        preexec_fn=limit_receiver,
        start_new_session=True,
    )
    try:
        status = process.wait(timeout=TRANSFER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        fail("rsync transfer exceeded its time limit")
    if status != 0:
        fail(f"rrsync rejected or failed the transfer with status {status}")


def open_lock(path: Path, *, owner: int) -> int:
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(descriptor)
        fail("deployment lock has unsafe metadata")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def main() -> int:
    owner = os.getuid()
    if owner == 0:
        fail("mirror receiver must not run as root")
    require_safe_ancestry(PROJECT_ROOT, leaf_owner=owner, leaf_mode=0o755)
    require_safe_ancestry(INCOMING_ROOT, leaf_owner=owner, leaf_mode=0o700)
    require_trusted_executable(RRSYNC, owner=0)

    original_command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    request_type, destination = parse_request(original_command)
    stage = Path(tempfile.mkdtemp(prefix="transfer-", dir=INCOMING_ROOT))
    os.chmod(stage, 0o700)
    try:
        run_rrsync(stage, original_command)
        root_entries = sorted(entry.name for entry in os.scandir(stage))
        expected_root = [destination]
        if root_entries != expected_root:
            fail("transfer created an unexpected staging tree")
        lock_descriptor = open_lock(LOCK_PATH, owner=owner)
        try:
            require_safe_ancestry(PROJECT_ROOT, leaf_owner=owner, leaf_mode=0o755)
            if request_type == "version":
                publish_version(stage / destination, PROJECT_ROOT / destination, owner=owner)
            else:
                publish_stable(
                    stage / destination,
                    destination,
                    project_root=PROJECT_ROOT,
                    owner=owner,
                )
        finally:
            os.close(lock_descriptor)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReceiverError as exc:
        print(f"mirror receiver: {exc}", file=sys.stderr)
        raise SystemExit(1)
