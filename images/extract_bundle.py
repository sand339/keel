#!/usr/bin/env python3
"""Extract a harness tarball without allowing writes outside its image root."""

from __future__ import annotations

import os
import posixpath
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath


def safe_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive path: {name}")
    return path


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ARCHIVE DESTINATION", file=sys.stderr)
        return 2
    destination = Path(sys.argv[2]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(sys.argv[1], "r:*") as archive:
        members = archive.getmembers()
        names: set[PurePosixPath] = set()
        for member in members:
            name = safe_name(member.name)
            if name in names:
                raise ValueError(f"duplicate archive path: {member.name}")
            names.add(name)
            if not (member.isdir() or member.isfile() or member.issym()):
                raise ValueError(f"unsupported archive entry: {member.name}")
            if member.issym():
                target = PurePosixPath(member.linkname)
                combined = posixpath.normpath(str(name.parent / target))
                if target.is_absolute() or combined == ".." or combined.startswith("../"):
                    raise ValueError(f"unsafe symlink target: {member.name}")

        for member in members:
            if member.isdir():
                path = destination / safe_name(member.name)
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(member.mode & 0o777)
        for member in members:
            if member.isfile():
                path = destination / safe_name(member.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"cannot read archive entry: {member.name}")
                with source, path.open("wb") as output:
                    shutil.copyfileobj(source, output)
                path.chmod(member.mode & 0o777)
        for member in members:
            if member.issym():
                path = destination / safe_name(member.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
