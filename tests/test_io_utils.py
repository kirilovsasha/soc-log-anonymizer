"""
Тесты для soc_log_anonymizer.io_utils: автоопределение кодировки,
прозрачная поддержка gzip-архивов, построчный стриминг (mmap/gzip/обычный
файл), проверка прав доступа.
"""

import gzip
import os
import stat
import tempfile
import unittest

from soc_log_anonymizer.io_utils import (
    check_world_readable,
    detect_file_encoding,
    is_gzip_file,
    iter_lines_mmap,
    iter_lines_stream,
    read_file_auto_encoding,
)


class TestGzipSupport(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.content = "src=192.168.1.10 user=jdoe\nвторая строка с кириллицей\n"

    def _make_gzip_file(self, name: str = "test.log.gz") -> str:
        path = os.path.join(self.tmpdir.name, name)
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write(self.content)
        return path

    def test_is_gzip_file_detects_by_magic_bytes(self):
        path = self._make_gzip_file()
        self.assertTrue(is_gzip_file(path))

    def test_is_gzip_file_true_without_gz_extension(self):
        """Магические байты проверяются независимо от расширения файла."""
        gz_path = self._make_gzip_file()
        no_ext_path = os.path.join(self.tmpdir.name, "no_extension_hint")
        os.rename(gz_path, no_ext_path)
        self.assertTrue(is_gzip_file(no_ext_path))

    def test_is_gzip_file_false_for_plain_text(self):
        path = os.path.join(self.tmpdir.name, "plain.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.content)
        self.assertFalse(is_gzip_file(path))

    def test_is_gzip_file_false_for_missing_file(self):
        self.assertFalse(is_gzip_file(os.path.join(self.tmpdir.name, "nope.gz")))

    def test_read_file_auto_encoding_decompresses_gzip(self):
        path = self._make_gzip_file()
        self.assertEqual(read_file_auto_encoding(path), self.content)

    def test_detect_file_encoding_on_gzip(self):
        path = self._make_gzip_file()
        self.assertEqual(detect_file_encoding(path), "utf-8")

    def test_iter_lines_stream_reads_gzip_transparently(self):
        path = self._make_gzip_file()
        lines = list(iter_lines_stream(path))
        self.assertEqual("".join(lines), self.content)

    def test_iter_lines_stream_ignores_mmap_flag_for_gzip(self):
        """--mmap должен молча игнорироваться для .gz — mmap работал бы
        со сжатыми байтами, а не с текстом."""
        path = self._make_gzip_file()
        lines = list(iter_lines_stream(path, use_mmap=True))
        self.assertEqual("".join(lines), self.content)

    def test_gzip_roundtrip_with_cyrillic_windows1251(self):
        path = os.path.join(self.tmpdir.name, "cyrillic.log.gz")
        text = "тестовая строка в windows-1251\n"
        with gzip.open(path, "wb") as f:
            f.write(text.encode("windows-1251"))
        self.assertEqual(read_file_auto_encoding(path), text)


class TestIterLinesStreamPlainFiles(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = os.path.join(self.tmpdir.name, "plain.log")
        self.content = "line one\nline two\nline three\n"
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(self.content)

    def test_stream_matches_plain_read(self):
        lines = list(iter_lines_stream(self.path))
        self.assertEqual("".join(lines), self.content)

    def test_stream_with_mmap_matches_plain_read(self):
        lines = list(iter_lines_stream(self.path, use_mmap=True))
        self.assertEqual("".join(lines), self.content)

    def test_iter_lines_mmap_matches_plain_read(self):
        lines = list(iter_lines_mmap(self.path))
        self.assertEqual("".join(lines), self.content)

    def test_iter_lines_mmap_empty_file(self):
        empty_path = os.path.join(self.tmpdir.name, "empty.log")
        open(empty_path, "w").close()
        self.assertEqual(list(iter_lines_mmap(empty_path)), [])


class TestCheckWorldReadable(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = os.path.join(self.tmpdir.name, "secret.txt")
        with open(self.path, "w") as f:
            f.write("s3cr3t")

    @unittest.skipUnless(os.name == "posix", "биты прав доступа rwx специфичны для POSIX")
    def test_warns_when_world_readable(self):
        os.chmod(self.path, 0o644)
        warning = check_world_readable(self.path)
        self.assertIsNotNone(warning)

    @unittest.skipUnless(os.name == "posix", "биты прав доступа rwx специфичны для POSIX")
    def test_no_warning_when_owner_only(self):
        os.chmod(self.path, 0o600)
        self.assertIsNone(check_world_readable(self.path))

    def test_missing_file_returns_none(self):
        self.assertIsNone(check_world_readable(os.path.join(self.tmpdir.name, "missing")))


if __name__ == "__main__":
    unittest.main()
