#!/usr/bin/env python3
"""Check or regenerate self-contained release-script safety primitives."""

import argparse
import os
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "scripts/release-safety-primitives.inc"
TARGETS = {
    ROOT / "scripts/prepare-release.sh": (
        "core_paths", "source_repo", "new_output", "bounded_copy", "sync_output",
    ),
    ROOT / "scripts/offline-sign-release.sh": (
        "core_paths", "input_paths", "new_output", "bounded_copy", "sync_output",
    ),
    ROOT / "scripts/publish-release.sh": (
        "core_paths", "input_paths", "source_repo", "bounded_copy",
    ),
}
START = "# BEGIN GENERATED RELEASE SAFETY PRIMITIVES\n"
END = "# END GENERATED RELEASE SAFETY PRIMITIVES\n"
COMPONENT_START = "# BEGIN COMPONENT "
COMPONENT_END = "# END COMPONENT "


def read_components() -> dict[str, str]:
    components: dict[str, str] = {}
    current = None
    body: list[str] = []
    for line in TEMPLATE.read_text(encoding="ascii").splitlines(keepends=True):
        if line.startswith(COMPONENT_START):
            if current is not None or not line.endswith("\n"):
                raise ValueError(f"invalid nested component in {TEMPLATE}")
            current = line.removeprefix(COMPONENT_START).strip()
            if not current or current in components:
                raise ValueError(f"invalid or duplicate component {current!r}")
            body = []
            continue
        if line.startswith(COMPONENT_END):
            name = line.removeprefix(COMPONENT_END).strip()
            if current is None or name != current:
                raise ValueError(f"mismatched component end {name!r} in {TEMPLATE}")
            component = "".join(body).strip("\n") + "\n"
            components[current] = component
            current = None
            body = []
            continue
        if current is None:
            if line.strip() and not line.startswith("#"):
                raise ValueError(f"content outside a component in {TEMPLATE}")
        else:
            body.append(line)
    if current is not None:
        raise ValueError(f"unterminated component {current!r} in {TEMPLATE}")
    selected = {name for names in TARGETS.values() for name in names}
    if selected != set(components):
        raise ValueError("template components and target selections differ")
    return components


def expected_block(components: dict[str, str], names: tuple[str, ...]) -> str:
    return START + "\n\n".join(components[name].rstrip("\n") for name in names) + "\n" + END


def replace_block(path: Path, expected: str) -> tuple[bool, str]:
    content = path.read_text(encoding="ascii")
    if content.count(START) != 1 or content.count(END) != 1:
        raise ValueError(f"{path} must contain exactly one generated-block marker pair")
    start = content.index(START)
    end = content.index(END, start) + len(END)
    updated = content[:start] + expected + content[end:]
    return updated != content, updated


def atomic_write(path: Path, content: str) -> None:
    mode = path.stat().st_mode & 0o777
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="ascii", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace each embedded block instead of only checking it",
    )
    args = parser.parse_args()

    components = read_components()
    stale = []
    for path, names in TARGETS.items():
        changed, updated = replace_block(path, expected_block(components, names))
        if not changed:
            continue
        stale.append(path)
        if args.write:
            atomic_write(path, updated)

    if stale and not args.write:
        for path in stale:
            print(f"stale generated release safety primitives: {path.relative_to(ROOT)}")
        print("run python3 -B scripts/sync-release-safety-primitives.py --write")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
