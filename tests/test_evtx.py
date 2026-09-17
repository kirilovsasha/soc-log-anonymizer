"""Tests for Windows Event Log (.evtx) conversion via wevtutil."""

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from soc_log_anonymizer.evtx import (
    EVTX_MAGIC,
    EvtxError,
    decode_wevtutil_output,
    is_evtx_file,
    read_evtx_text,
    wevtutil_argv,
)
from soc_log_anonymizer.io_utils import iter_log_lines, read_log_file


class TestEvtxDetect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_magic_bytes(self):
        path = os.path.join(self.tmp.name, "Security.bin")
        with open(path, "wb") as handle:
            handle.write(EVTX_MAGIC + b"\x00\x01")
        self.assertTrue(is_evtx_file(path))

    def test_extension_without_magic(self):
        path = os.path.join(self.tmp.name, "export.evtx")
        with open(path, "wb") as handle:
            handle.write(b"not-an-evtx")
        self.assertTrue(is_evtx_file(path))

    def test_plain_log_is_not_evtx(self):
        path = os.path.join(self.tmp.name, "auth.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("src=10.0.0.1\n")
        self.assertFalse(is_evtx_file(path))

    def test_missing_file(self):
        self.assertFalse(is_evtx_file(os.path.join(self.tmp.name, "missing.evtx")))


class TestWevtutilDecode(unittest.TestCase):
    def test_utf16_le_bom(self):
        text = "Event[0]:\n  Account Name:\tadmin\n"
        raw = text.encode("utf-16")  # LE + BOM on Windows/little-endian
        self.assertIn("Account Name:", decode_wevtutil_output(raw))
        self.assertIn("admin", decode_wevtutil_output(raw))

    def test_utf8(self):
        raw = b"Event[0]:\n  Computer: HOST\n"
        self.assertEqual(decode_wevtutil_output(raw), "Event[0]:\n  Computer: HOST\n")

    def test_empty(self):
        self.assertEqual(decode_wevtutil_output(b""), "")


class TestReadEvtxText(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "Security.evtx")
        with open(self.path, "wb") as handle:
            handle.write(EVTX_MAGIC + b"\x00")

    def test_non_windows_raises(self):
        if sys.platform == "win32":
            self.skipTest("this assertion is for POSIX CI")
        with self.assertRaises(EvtxError) as ctx:
            read_evtx_text(self.path)
        self.assertIn("Windows", str(ctx.exception))

    def test_mocked_wevtutil_roundtrip(self):
        payload = "Event[0]:\n  Account Name:\tjdoe\n".encode("utf-16")
        completed = mock.Mock(returncode=0, stdout=payload, stderr=b"")
        runner = mock.Mock(return_value=completed)
        with mock.patch("soc_log_anonymizer.evtx.sys.platform", "win32"), \
                mock.patch("soc_log_anonymizer.winsec.sys.platform", "win32"), \
                mock.patch("soc_log_anonymizer.evtx.find_wevtutil", return_value="wevtutil"):
            text = read_evtx_text(self.path, runner=runner, timeout=5)
        self.assertIn("jdoe", text)
        argv = runner.call_args[0][0]
        self.assertEqual(argv[:2], ["wevtutil", "qe"])
        self.assertIn("/lf:true", argv)
        self.assertIn("/f:text", argv)
        self.assertIn("/uni:true", argv)
        self.assertEqual(
            runner.call_args.kwargs.get("creationflags"),
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        )

    def test_wevtutil_argv_uses_absolute_path(self):
        argv = wevtutil_argv(self.path, wevtutil="wevtutil.exe")
        self.assertEqual(argv[0], "wevtutil.exe")
        self.assertTrue(os.path.isabs(argv[2]))

    def test_nonzero_exit_raises(self):
        completed = mock.Mock(returncode=1, stdout=b"", stderr=b"The specified file is not an Event Log.")
        with mock.patch("soc_log_anonymizer.evtx.sys.platform", "win32"), \
                mock.patch("soc_log_anonymizer.evtx.find_wevtutil", return_value="wevtutil"), \
                self.assertRaises(EvtxError):
            read_evtx_text(self.path, runner=mock.Mock(return_value=completed))

    def test_timeout_raises(self):
        def _runner(*_a, **_k):
            raise subprocess.TimeoutExpired(cmd="wevtutil", timeout=1)

        with mock.patch("soc_log_anonymizer.evtx.sys.platform", "win32"), \
                mock.patch("soc_log_anonymizer.evtx.find_wevtutil", return_value="wevtutil"), \
                self.assertRaises(EvtxError) as ctx:
            read_evtx_text(self.path, runner=_runner, timeout=1)
        self.assertIn("не успел", str(ctx.exception))

    def test_read_log_file_uses_wevtutil(self):
        payload = b"Event[0]:\n  src=10.1.2.3\n"
        completed = mock.Mock(returncode=0, stdout=payload, stderr=b"")
        with mock.patch("soc_log_anonymizer.evtx.sys.platform", "win32"), \
                mock.patch("soc_log_anonymizer.evtx.find_wevtutil", return_value="wevtutil"), \
                mock.patch("soc_log_anonymizer.evtx.subprocess.run", return_value=completed):
            text = read_log_file(self.path)
        self.assertIn("10.1.2.3", text)

    def test_iter_log_lines_evtx(self):
        payload = b"line-one\nline-two\n"
        completed = mock.Mock(returncode=0, stdout=payload, stderr=b"")
        with mock.patch("soc_log_anonymizer.evtx.sys.platform", "win32"), \
                mock.patch("soc_log_anonymizer.evtx.find_wevtutil", return_value="wevtutil"), \
                mock.patch("soc_log_anonymizer.evtx.subprocess.run", return_value=completed):
            lines = list(iter_log_lines(self.path))
        self.assertEqual([line.strip() for line in lines], ["line-one", "line-two"])

    def test_read_log_file_plain_text_unchanged(self):
        path = os.path.join(self.tmp.name, "auth.log")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("user=admin\n")
        self.assertEqual(read_log_file(path), "user=admin\n")


if __name__ == "__main__":
    unittest.main()
