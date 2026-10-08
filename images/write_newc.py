#!/usr/bin/env python3
"""Write a deterministic Linux newc initramfs from a directory."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import BinaryIO


class Writer:
    """Count bytes while writing to a possibly non-seekable stream."""

    def __init__(self, raw: BinaryIO) -> None:
        self.raw = raw
        self.offset = 0

    def write(self, data: bytes) -> None:
        self.raw.write(data)
        self.offset += len(data)


def pad(output: Writer, alignment: int) -> None:
    remainder = output.offset % alignment
    if remainder:
        output.write(b"\0" * (alignment - remainder))


def entries(root: Path) -> list[Path]:
    return [root, *sorted(root.rglob("*"), key=lambda path: os.fsencode(path.relative_to(root)))]


def write_entry(output: Writer, root: Path, path: Path, inode: int) -> None:
    metadata = path.lstat()
    name = b"." if path == root else b"./" + os.fsencode(path.relative_to(root))
    if stat.S_ISREG(metadata.st_mode):
        data = path.read_bytes()
    elif stat.S_ISLNK(metadata.st_mode):
        data = os.fsencode(os.readlink(path))
    else:
        data = b""
    rdev_major = os.major(metadata.st_rdev) if metadata.st_rdev else 0
    rdev_minor = os.minor(metadata.st_rdev) if metadata.st_rdev else 0
    fields = (
        inode,
        metadata.st_mode,
        0,
        0,
        2 if stat.S_ISDIR(metadata.st_mode) else 1,
        0,
        len(data),
        0,
        0,
        rdev_major,
        rdev_minor,
        len(name) + 1,
        0,
    )
    output.write(b"070701" + b"".join(f"{field:08x}".encode() for field in fields))
    output.write(name + b"\0")
    pad(output, 4)
    output.write(data)
    pad(output, 4)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} ROOT", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    output = Writer(sys.stdout.buffer)
    for inode, path in enumerate(entries(root), start=1):
        write_entry(output, root, path, inode)
    trailer = b"TRAILER!!!"
    fields = (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer) + 1, 0)
    output.write(b"070701" + b"".join(f"{field:08x}".encode() for field in fields))
    output.write(trailer + b"\0")
    pad(output, 4)
    pad(output, 512)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
