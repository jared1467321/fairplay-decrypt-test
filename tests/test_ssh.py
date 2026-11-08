"""Check direct SSH routing and retrieval without touching a real device."""

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "credential-retrieval"))
import native_ssh  # noqa: E402
import retrieve  # noqa: E402


class TransportTests(unittest.TestCase):
    def test_direct_ssh_skips_usb_and_uses_requested_key(self) -> None:
        with (
            patch.object(native_ssh.socket, "create_connection") as socket,
            patch.object(native_ssh.subprocess, "Popen") as popen,
            patch.object(native_ssh.subprocess, "run") as run,
        ):
            run.return_value = MagicMock(returncode=0, stdout=b"")
            device = native_ssh.SSHDevice(
                2200, None, host="iphone.tailnet.ts.net", identity=Path("/tmp/key")
            )
            device.run("echo ready")
            self.assertEqual(device.command[-1], "iphone.tailnet.ts.net")
            self.assertIn("2200", device.command)
            self.assertIn("/tmp/key", device.command)
            self.assertIn("BatchMode=yes", device.command)
            socket.assert_not_called()
            popen.assert_not_called()

    def test_password_is_passed_only_in_environment(self) -> None:
        with (
            patch.dict(os.environ, {"DEVICE_PASSWORD": "test-secret"}),
            patch.object(native_ssh.subprocess, "run") as run,
        ):
            run.return_value = MagicMock(returncode=0, stdout=b"")
            device = native_ssh.SSHDevice(
                22, None, host="100.64.0.5", password_env="DEVICE_PASSWORD"
            )
            device.run("echo ready")
            self.assertEqual(device.command[:2], ["sshpass", "-e"])
            self.assertIn("BatchMode=no", device.command)
            self.assertNotIn("test-secret", " ".join(device.command))
            self.assertEqual(run.call_args.kwargs["env"]["SSHPASS"], "test-secret")

    def test_missing_password_fails_before_connecting(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(native_ssh.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(ValueError, "empty or unset"):
                native_ssh.SSHDevice(22, None, host="phone", password_env="MISSING")
            run.assert_not_called()

    def test_usb_can_still_use_existing_tunnel(self) -> None:
        with (
            patch.object(native_ssh.socket, "create_connection") as socket,
            patch.object(native_ssh.subprocess, "run") as run,
        ):
            run.return_value = MagicMock(returncode=0, stdout=b"")
            device = native_ssh.SSHDevice(2222, "a" * 40)
            socket.assert_called_once_with(("127.0.0.1", 2222), timeout=1)
            self.assertEqual(device.command[-1], "127.0.0.1")

    def test_password_environment_reaches_observer_and_fallback_processes(self) -> None:
        device = MagicMock()
        device.command = ["sshpass", "-e", "ssh", "root@phone"]
        device.env = {"SSHPASS": "test-secret"}
        device.processes.return_value = b""
        observer, trigger, direct = MagicMock(), MagicMock(), MagicMock()
        observer.stderr.readline.return_value = b"observing FairPlay requests\n"
        observer.communicate.return_value = (b"", b"")
        observer.returncode = 0
        trigger.communicate.return_value = (b"", b"")
        trigger.returncode = 3  # Exercise the direct-execution fallback too.
        observer.poll.return_value = trigger.poll.return_value = (
            direct.poll.return_value
        ) = 0
        with (
            patch.object(retrieve.select, "select", return_value=([1], [], [])),
            patch.object(
                retrieve.subprocess, "Popen", side_effect=[observer, trigger, direct]
            ) as popen,
        ):
            retrieve.observe_uid_layer(
                device, "/helper", 123, "/output", "/trigger", "/app/Test"
            )
        self.assertEqual(popen.call_count, 3)
        for call in popen.call_args_list:
            self.assertEqual(call.kwargs["env"], device.env)
            self.assertNotIn("test-secret", " ".join(call.args[0]))


class RetrievalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        for name in retrieve.DEVICE_FILES:
            (self.bundle / name).write_bytes(b"synthetic helper")
        self.output = self.root / "credential-output"
        self.device = MagicMock()
        self.device.trigger_directory = "/var/tmp/test-trigger"
        self.device.path.side_effect = lambda name: "/var/tmp/test/" + name
        self.device.write.side_effect = (
            lambda name, *_args, **_kwargs: "/var/tmp/test/" + name
        )
        self.device.read.side_effect = lambda path: (
            b"a" * 20 if path.endswith("device-udid.bin") else b"c" * 16
        )

    def run_retrieval(self, *options: str) -> MagicMock:
        def atom(tag: bytes, payload: bytes) -> bytes:
            return struct.pack(">I", len(payload) + 8) + tag + payload

        sinf = atom(b"sinf", atom(b"schi", atom(b"key ", b"\0\0\0\1")))
        args = [
            "retrieve.py",
            "--ssh-host",
            "phone.tailnet.ts.net",
            "--bundle",
            str(self.bundle),
            "--output-dir",
            str(self.output),
            *options,
        ]
        with (
            patch.object(sys, "argv", args),
            patch.object(retrieve, "SSHDevice", return_value=self.device) as factory,
            patch.object(
                retrieve,
                "connected_udid",
                side_effect=AssertionError("USB discovery used"),
            ),
            patch.object(
                retrieve, "trigger_app", return_value=("/app/Test.app", "Test", sinf)
            ),
            patch.object(retrieve, "restart_fairplayd", return_value=123),
            patch.object(retrieve, "observe_uid_layer"),
        ):
            retrieve.main()
        return factory

    def test_remote_retrieval_needs_no_local_udid_or_usb(self) -> None:
        factory = self.run_retrieval()
        self.assertEqual(factory.call_args.args, (22, None))
        self.assertEqual(factory.call_args.kwargs["host"], "phone.tailnet.ts.net")
        self.assertEqual((self.output / "credential.bin").read_bytes(), b"c" * 16)
        self.assertEqual((self.output / "credential.bin").stat().st_mode & 0o777, 0o600)
        self.device.cleanup.assert_called_once()

    def test_optional_udid_rejects_wrong_device_and_cleans_up(self) -> None:
        with self.assertRaisesRegex(ValueError, "different device"):
            self.run_retrieval("--device-udid", "b" * 40)
        self.device.cleanup.assert_called_once()
        self.assertFalse(self.output.exists())

    def test_invalid_credential_is_not_saved(self) -> None:
        self.device.read.side_effect = lambda path: (
            b"a" * 20 if path.endswith("device-udid.bin") else b"short"
        )
        with self.assertRaisesRegex(ValueError, "invalid credential"):
            self.run_retrieval()
        self.device.cleanup.assert_called_once()
        self.assertFalse(self.output.exists())

    def test_ssh_port_and_password_option_are_forwarded(self) -> None:
        factory = self.run_retrieval(
            "--ssh-port", "2223", "--ssh-password-env", "IPHONE_SSH_PASS"
        )
        self.assertEqual(factory.call_args.args[0], 2223)
        self.assertEqual(factory.call_args.kwargs["password_env"], "IPHONE_SSH_PASS")


if __name__ == "__main__":
    unittest.main()
