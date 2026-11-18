#!/usr/bin/env python3
"""Build a Linux amd64 release on /build and publish its archive/checksum."""
import datetime
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile

PROJECT = "mariadb-mcp"


def verify_archive(path):
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise ValueError("empty release archive")
        for member in members:
            parts = PurePosixPath(member.name).parts
            if (not parts or parts[0] != PROJECT or ".." in parts
                    or not (member.isdir() or member.isfile())):
                raise ValueError("unsafe release archive entry")


def publish(source, destination):
    fd, temporary = tempfile.mkstemp(prefix=".mariadb-mcp-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)


def main():
    if len(sys.argv) != 1:
        raise SystemExit("Usage: python3 deploy/package.py")
    root = Path(__file__).resolve().parents[1]
    build = Path("/build")
    if not build.is_mount() or shutil.disk_usage(build).free < 256 * 1024**2:
        raise SystemExit("A mounted /build with sufficient free space is required")
    environment = dict(os.environ, GOCACHE="/build/cache", GOMODCACHE="/build/mod",
                       GOTMPDIR="/build/tmp", TMPDIR="/build/tmp", CGO_ENABLED="0",
                       GOOS="linux", GOARCH="amd64")
    for directory in ("/build/cache", "/build/mod", "/build/tmp"):
        with tempfile.TemporaryFile(dir=directory):
            pass
    dist = root / "dist"
    if dist.is_symlink():
        raise SystemExit("Refusing a symlinked distribution directory")
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mariadb-mcp-release-", dir="/build/tmp") as temporary:
        work = Path(temporary)
        release = work / PROJECT
        (release / "bin").mkdir(parents=True)
        subprocess.run(["go", "build", "-buildvcs=false", "-trimpath", "-ldflags=-s -w",
                        "-o", str(release / "bin/mariadb-mcp"), "./cmd/mariadb-mcp"],
                       cwd=root, env=environment, check=True)
        sources = [root / "README.md", root / "LICENSE"]
        sources += sorted((root / "docs").glob("*.md"))
        sources += [root / "deploy" / name for name in
                    ("README.md", "install.sh", "mariadb-mcp.service", "nginx.conf.example")]
        sources += sorted(p for p in (root / "examples").rglob("*")
                          if p.name.endswith(".example.json") or p.suffix in (".md", ".sql"))
        for source in sources:
            if source.is_symlink() or not source.is_file():
                raise ValueError("release inputs must be regular files")
            destination = release / source.relative_to(root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        name = f"{PROJECT}-linux-amd64-{timestamp}.tar.gz"
        archive = work / name
        with tarfile.open(archive, "w:gz") as output:
            output.add(release, arcname=PROJECT)
        verify_archive(archive)
        checksum = work / (name + ".sha256")
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        checksum.write_text(digest + "  " + name + "\n")
        destination = dist / name
        publish(archive, destination)
        try:
            publish(checksum, dist / checksum.name)
        except BaseException:
            destination.unlink()
            raise
        print(destination)
        print(dist / checksum.name)


if __name__ == "__main__":
    main()
