#!/usr/bin/python3
"""Restricted rsync receiver for the official linux-temp-admin mirror."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import ctypes
import datetime as dt
import errno
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
import time


PROJECT_ROOT = Path("/www/wwwroot/dl.ll.cd/linux-temp-admin")
INCOMING_ROOT = Path("/var/lib/linux-temp-admin-mirror")
LOCK_PATH = INCOMING_ROOT / ".deploy.lock"
RRSYNC = Path("/usr/bin/rrsync")
MIRROR_BASE_URL = "https://dl.ll.cd/linux-temp-admin"
TRANSFER_TIMEOUT_SECONDS = 300
STAGING_SCAN_INTERVAL_SECONDS = 0.1
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_RELEASE_VERSION_BYTES = 128
MAX_RELEASE_TAG_BYTES = MAX_RELEASE_VERSION_BYTES + 1

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
# A complete release can contain two maximum-size binaries and four metadata
# files. Leave a second copy's worth of headroom for rsync --delay-updates
# temporaries, while bounding a compromised deployment identity before the
# exact release-tree validation runs.
MAX_STAGING_BYTES = 2 * (2 * MAX_BINARY_BYTES + 4 * MAX_METADATA_BYTES)
MAX_STAGING_FILES = 32
MAX_STAGING_ENTRIES = 64
# A stolen deployment identity must not be able to fill the public filesystem by
# serially publishing checksum-consistent but unsigned future version trees.
# The free-space reserve is the immediate hard stop; the aggregate limits also
# bound inode and long-term namespace growth even on a very large filesystem.
MAX_PROJECT_BYTES = 32 * 1024 * 1024 * 1024
MAX_PROJECT_FILES = 8192
MAX_PROJECT_ENTRIES = 16384
MAX_PROJECT_VERSIONS = 1024
MIN_PROJECT_AVAILABLE_BYTES = 1024 * 1024 * 1024
MIN_PROJECT_AVAILABLE_PERCENT = 5
VersionKey = tuple[tuple[int, str], tuple[int, str], tuple[int, str]]
AT_FDCWD = -100
RENAME_NOREPLACE = 1

LIBC = ctypes.CDLL(None, use_errno=True)
RENAMEAT2 = getattr(LIBC, "renameat2", None)
if RENAMEAT2 is not None:
    RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    RENAMEAT2.restype = ctypes.c_int


class ReceiverError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReceiverError(message)


@contextmanager
def unmasked_creation() -> Iterator[None]:
    # The receiver is single-threaded. Set exact modes at creation so a crash
    # cannot preserve an object whose permissions were reduced by the caller's
    # umask before the following metadata validation runs.
    previous_umask = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous_umask)


def release_version_tuple(
    tag: str, *, stable: bool
) -> VersionKey:
    if len(tag) > MAX_RELEASE_TAG_BYTES:
        kind = "stable metadata" if stable else "release destination"
        fail(f"{kind} exceeds the {MAX_RELEASE_TAG_BYTES}-byte tag limit")
    match = VERSION_PATTERN.fullmatch(tag)
    if match is None or (stable and match.group(4) is not None):
        kind = "stable metadata" if stable else "release destination"
        fail(f"{kind} must name a canonical {'non-prerelease ' if stable else ''}tag")
    major = match.group(1)
    if major in ("0", "1"):
        fail("release versions below v2 are not accepted")
    # Canonical numeric components have no leading zeroes, so length followed by
    # lexical bytes is arbitrary-precision numeric order without Python's
    # interpreter-dependent decimal-to-int digit limit.
    components = tuple(match.group(index) for index in range(1, 4))
    return tuple((len(component), component) for component in components)


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
        if VERSION_PATTERN.fullmatch(version) is None:
            fail("destination is not an allowed stable file or canonical version directory")
        release_version_tuple(version, stable=False)
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


def stable_version_tuple(
    tag: str,
) -> VersionKey:
    return release_version_tuple(tag, stable=True)


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
) -> tuple[VersionKey, bytes] | None:
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


def rename_noreplace(source: Path, destination: Path) -> None:
    if RENAMEAT2 is None:
        fail("renameat2(RENAME_NOREPLACE) is unavailable on the mirror host")
    ctypes.set_errno(0)
    result = RENAMEAT2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            fail(f"immutable release file appeared concurrently: {destination}")
        fail(
            "cannot atomically publish immutable release file "
            f"{destination}: {os.strerror(error_number)}"
        )


def cleanup_private_temps(directory: Path, labels: tuple[str, ...], *, owner: int) -> None:
    patterns = {
        label: re.compile(rf"[.]mirror-{re.escape(label)}-[0-9a-f]{{32}}")
        for label in labels
    }
    cleaned = False
    with os.scandir(directory) as entries:
        for entry in entries:
            label = next(
                (name for name, pattern in patterns.items() if pattern.fullmatch(entry.name)),
                None,
            )
            if label is None:
                continue
            path = directory / entry.name
            info = lstat(path)
            maximum = MAX_BINARY_BYTES if label in (
                "linux-temp-admin-linux-amd64",
                "linux-temp-admin-linux-arm64",
            ) else MAX_METADATA_BYTES
            if (
                not stat.S_ISREG(info.st_mode)
                or path.is_symlink()
                or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) not in (0o600, 0o644)
                or info.st_size < 0
                or info.st_size > maximum
                or info.st_nlink not in (1, 2)
            ):
                fail(f"unsafe stale mirror temporary file: {path}")
            if info.st_nlink == 2:
                destination_info = lstat(directory / label)
                if (
                    not stat.S_ISREG(destination_info.st_mode)
                    or destination_info.st_dev != info.st_dev
                    or destination_info.st_ino != info.st_ino
                ):
                    fail(f"stale mirror temporary file has an unexpected hard link: {path}")
            path.unlink()
            cleaned = True
    if cleaned:
        fsync_directory(directory)


def copy_to_private_temp(source: Path, directory: Path, label: str) -> Path:
    temporary = directory / f".mirror-{label}-{secrets.token_hex(16)}"
    with unmasked_creation():
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
    release_version_tuple(destination.name, stable=False)
    validate_version(staged, owner=owner)
    for name in EXPECTED_VERSION_FILES:
        os.chmod(staged / name, 0o644, follow_symlinks=False)
        fsync_file(staged / name)
    if destination.exists() or destination.is_symlink():
        require_directory(destination, owner=owner, mode=0o755)
        cleanup_private_temps(destination, EXPECTED_VERSION_FILES, owner=owner)
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
        existing = []
    missing = [name for name in EXPECTED_VERSION_FILES if name not in existing]
    additional_bytes = sum(allocated_or_logical_bytes(staged / name) for name in missing)
    additional_entries = len(missing)
    additional_versions = 0
    if not destination.exists():
        # Reserve generous metadata headroom for the new directory itself.
        additional_bytes += MAX_METADATA_BYTES
        additional_entries += 1
        additional_versions = 1
    require_project_budget(
        destination.parent,
        additional_bytes=additional_bytes,
        additional_files=len(missing),
        additional_entries=additional_entries,
        additional_versions=additional_versions,
    )
    if not destination.exists():
        try:
            with unmasked_creation():
                os.mkdir(destination, 0o755)
        except FileExistsError:
            fail(f"version destination appeared concurrently: {destination}")
        require_directory(destination, owner=owner, mode=0o755)
    # Repeat this for an existing directory too: it may be the visible but not
    # yet durable result of an interrupted mkdir from the previous invocation.
    fsync_directory(destination.parent)
    try:
        for name in EXPECTED_VERSION_FILES:
            if (destination / name).exists() or (destination / name).is_symlink():
                continue
            temporary = copy_to_private_temp(staged / name, destination, name)
            try:
                rename_noreplace(temporary, destination / name)
                fsync_directory(destination)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        validate_version(destination, owner=owner, published=True)
    except BaseException:
        # Valid files already committed into an incomplete version are deliberately
        # retained. A retry may fill the missing files but can never replace one;
        # narrowly validated private temporaries from an interrupted commit are
        # removed under the deployment lock before that retry validates the directory.
        raise
    fsync_directory(destination)
    require_project_budget(destination.parent)


def matching_stable_installer_versions(
    project_root: Path, installer: Path, *, owner: int
) -> list[VersionKey]:
    matches: list[VersionKey] = []
    with os.scandir(project_root) as entries:
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            try:
                version = stable_version_tuple(entry.name)
            except ReceiverError:
                continue
            version_dir = project_root / entry.name
            try:
                validate_version(version_dir, owner=owner, published=True)
            except ReceiverError:
                continue
            if files_equal(installer, version_dir / "install.sh"):
                matches.append(version)
    return matches


def atomic_replace(staged: Path, destination: Path, *, project_root: Path, owner: int) -> None:
    require_regular(staged, owner=owner, maximum=MAX_METADATA_BYTES)
    os.chmod(staged, 0o644, follow_symlinks=False)
    fsync_file(staged)
    cleanup_private_temps(project_root, (destination.name,), owner=owner)
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
    require_project_budget(
        project_root,
        additional_bytes=allocated_or_logical_bytes(staged),
        additional_files=1,
        additional_entries=1,
    )
    atomic_replace(staged, project_root / name, project_root=project_root, owner=owner)
    require_project_budget(project_root)


def limit_receiver() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BINARY_BYTES, MAX_BINARY_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def allocated_or_logical_bytes(path: Path) -> int:
    info = lstat(path)
    return max(info.st_size, info.st_blocks * 512)


def require_tree_budget(
    root: Path,
    *,
    label: str,
    maximum_bytes: int,
    maximum_files: int,
    maximum_entries: int,
    additional_bytes: int = 0,
    additional_files: int = 0,
    additional_entries: int = 0,
    maximum_versions: int | None = None,
    additional_versions: int = 0,
) -> tuple[int, int, int, int]:
    total_bytes = additional_bytes
    file_count = additional_files
    entry_count = additional_entries
    version_count = additional_versions
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    if total_bytes > maximum_bytes:
        fail(f"{label} exceeds the total-byte limit of {maximum_bytes}")
    if file_count > maximum_files:
        fail(f"{label} exceeds the file limit of {maximum_files}")
    if entry_count > maximum_entries:
        fail(f"{label} exceeds the directory-entry limit of {maximum_entries}")
    if maximum_versions is not None and version_count > maximum_versions:
        fail(f"{label} exceeds the release-version limit of {maximum_versions}")
    try:
        root_descriptor = os.open(root, directory_flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")

    def walk(descriptor: int, *, root_level: bool) -> None:
        nonlocal total_bytes, file_count, entry_count, version_count
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > maximum_entries:
                        fail(
                            f"{label} exceeds the directory-entry limit "
                            f"of {maximum_entries}"
                        )
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        # rsync may rename a delay-update temporary while it is
                        # being scanned. The next scan or final scan sees its
                        # replacement. Project scans run under the deployment
                        # lock, so a disappearance there is external drift.
                        if label == "rsync staging tree":
                            continue
                        fail(f"mirror project entry disappeared during inspection: {entry.name}")
                    total_bytes += max(info.st_size, info.st_blocks * 512)
                    if total_bytes > maximum_bytes:
                        fail(f"{label} exceeds the total-byte limit of {maximum_bytes}")
                    if stat.S_ISDIR(info.st_mode):
                        if root_level and VERSION_PATTERN.fullmatch(entry.name):
                            if len(entry.name) > MAX_RELEASE_TAG_BYTES:
                                fail(f"{label} contains an overlong release-version directory")
                            version_count += 1
                            if maximum_versions is not None and version_count > maximum_versions:
                                fail(
                                    f"{label} exceeds the release-version limit "
                                    f"of {maximum_versions}"
                                )
                        try:
                            child = os.open(entry.name, directory_flags, dir_fd=descriptor)
                        except OSError as exc:
                            if label == "rsync staging tree" and exc.errno in (
                                errno.ENOENT,
                                errno.ENOTDIR,
                                errno.ELOOP,
                            ):
                                continue
                            fail(f"cannot open {label} directory: {exc}")
                        try:
                            walk(child, root_level=False)
                        finally:
                            os.close(child)
                    else:
                        file_count += 1
                        if file_count > maximum_files:
                            fail(f"{label} exceeds the file limit of {maximum_files}")
        except OSError as exc:
            fail(f"cannot inspect {label} usage: {exc}")

    try:
        walk(root_descriptor, root_level=True)
    finally:
        os.close(root_descriptor)
    return total_bytes, file_count, entry_count, version_count


def require_staging_budget(staging_root: Path) -> None:
    require_tree_budget(
        staging_root,
        label="rsync staging tree",
        maximum_bytes=MAX_STAGING_BYTES,
        maximum_files=MAX_STAGING_FILES,
        maximum_entries=MAX_STAGING_ENTRIES,
    )


def require_project_budget(
    project_root: Path,
    *,
    additional_bytes: int = 0,
    additional_files: int = 0,
    additional_entries: int = 0,
    additional_versions: int = 0,
) -> None:
    require_tree_budget(
        project_root,
        label="mirror project tree",
        maximum_bytes=MAX_PROJECT_BYTES,
        maximum_files=MAX_PROJECT_FILES,
        maximum_entries=MAX_PROJECT_ENTRIES,
        additional_bytes=additional_bytes,
        additional_files=additional_files,
        additional_entries=additional_entries,
        maximum_versions=MAX_PROJECT_VERSIONS,
        additional_versions=additional_versions,
    )
    try:
        filesystem = os.statvfs(project_root)
    except OSError as exc:
        fail(f"cannot inspect mirror project filesystem capacity: {exc}")
    capacity = filesystem.f_blocks * filesystem.f_frsize
    proportional_reserve = (
        capacity * MIN_PROJECT_AVAILABLE_PERCENT + 99
    ) // 100
    reserve = max(MIN_PROJECT_AVAILABLE_BYTES, proportional_reserve)
    available = filesystem.f_bavail * filesystem.f_frsize
    required = additional_bytes + reserve
    if available < required:
        fail(
            "mirror project filesystem would fall below its available-byte reserve "
            f"of {reserve}"
        )


def kill_transfer(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


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
        deadline = time.monotonic() + TRANSFER_TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("rsync transfer exceeded its time limit")
            try:
                status = process.wait(
                    timeout=min(STAGING_SCAN_INTERVAL_SECONDS, remaining)
                )
                break
            except subprocess.TimeoutExpired:
                # Count every current and residual transfer tree, not only this
                # session. The deployment lock is included; its fixed metadata
                # is negligible and including it avoids a pathname exception.
                require_staging_budget(stage.parent)
        if status != 0:
            fail(f"rrsync rejected or failed the transfer with status {status}")
        # Close the race between the final periodic scan and process exit before any
        # release validation or publication begins.
        require_staging_budget(stage.parent)
    except BaseException as operation_error:
        # No catchable receiver exit may leave a writer outside the deployment
        # lock. The separate session lets one signal terminate rrsync and every
        # rsync descendant before the lock can be released.
        if process.returncode is None:
            try:
                kill_transfer(process)
            except BaseException as cleanup_error:
                raise operation_error from cleanup_error
        raise


def remove_staging_tree(stage: Path) -> None:
    try:
        shutil.rmtree(stage)
    except FileNotFoundError:
        pass
    except OSError as exc:
        fail(f"cannot remove rsync staging tree: {exc}")
    # A successful session must not hide residue left by another interrupted
    # session. Keep this under the deployment lock so the aggregate is stable
    # except for the receiver's own completed cleanup.
    require_staging_budget(stage.parent)


def finish_staging_tree(stage: Path, operation_error: BaseException | None) -> None:
    try:
        remove_staging_tree(stage)
    except ReceiverError as cleanup_error:
        if operation_error is None:
            raise
        if isinstance(operation_error, ReceiverError):
            operation_error.args = (
                f"{operation_error}; additionally, {cleanup_error}",
            )
        raise operation_error from cleanup_error
    if operation_error is not None:
        raise operation_error


def open_lock(path: Path, *, owner: int, nonblocking: bool = False) -> int:
    with unmasked_creation():
        descriptor = os.open(
            path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
        )
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(descriptor)
        fail("deployment lock has unsafe metadata")
    operation = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
    try:
        fcntl.flock(descriptor, operation)
    except BlockingIOError:
        os.close(descriptor)
        fail("another mirror deployment is already active")
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
    # Serialize before creating staging state so byte/inode budgets cannot be
    # multiplied by concurrent sessions using the same deployment key.
    lock_descriptor = open_lock(LOCK_PATH, owner=owner, nonblocking=True)
    stage: Path | None = None
    try:
        # Refuse a new transfer if interrupted sessions already exhausted the
        # aggregate incoming-root budget.
        require_staging_budget(INCOMING_ROOT)
        with unmasked_creation():
            stage = Path(tempfile.mkdtemp(prefix="transfer-", dir=INCOMING_ROOT))
        operation_error: BaseException | None = None
        try:
            require_directory(stage, owner=owner, mode=0o700)
            require_staging_budget(INCOMING_ROOT)
            run_rrsync(stage, original_command)
            root_entries = sorted(entry.name for entry in os.scandir(stage))
            expected_root = [destination]
            if root_entries != expected_root:
                fail("transfer created an unexpected staging tree")
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
        except BaseException as exc:
            operation_error = exc
        finish_staging_tree(stage, operation_error)
    finally:
        os.close(lock_descriptor)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReceiverError as exc:
        print(f"mirror receiver: {exc}", file=sys.stderr)
        raise SystemExit(1)
