#!/usr/bin/env python3
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("release_package", Path(__file__).with_name("package.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTests(unittest.TestCase):
    def test_archive_layout(self):
        for name in ("mariadb-mcp/bin/mariadb-mcp", "bin/mariadb-mcp",
                     "/mariadb-mcp/bin/tool", "mariadb-mcp/../outside"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "release.tar.gz"
                with tarfile.open(path, "w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.size = 4
                    archive.addfile(member, io.BytesIO(b"data"))
                if name == "mariadb-mcp/bin/mariadb-mcp":
                    package.verify_archive(path)
                else:
                    with self.assertRaises(ValueError):
                        package.verify_archive(path)

    def test_archive_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                member = tarfile.TarInfo("mariadb-mcp/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                archive.addfile(member)
            with self.assertRaises(ValueError):
                package.verify_archive(path)

    def test_publication_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = (Path(temporary) / n for n in ("source", "destination"))
            source.write_bytes(b"release")
            package.publish(source, destination)
            self.assertEqual(destination.read_bytes(), b"release")
            source.write_bytes(b"replacement")
            with self.assertRaises(FileExistsError):
                package.publish(source, destination)
            self.assertEqual(destination.read_bytes(), b"release")
            self.assertFalse(list(Path(temporary).glob(".mariadb-mcp-*")))


if __name__ == "__main__":
    unittest.main()
