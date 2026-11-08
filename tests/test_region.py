"""Exercise region selection with a small, synthetic encrypted IPA."""

import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from core import ARM64, derive_page_key

ROOT = Path(__file__).resolve().parents[1]
CREDENTIAL = bytes(range(16))
PLAINTEXT = bytes(range(256)) * 16


def atom(tag: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + tag + payload


def make_ipa(path: Path) -> None:
    name, iviv, work = b"test-app", b"i" * 16, b"w" * 16
    clear = bytearray(448)
    clear[:4], clear[20:24], clear[24:40], clear[44:48] = (
        b"itun",
        b"key ",
        work,
        b"iviv",
    )
    wrapping = Cipher(
        algorithms.AES(bytes(b ^ 0x30 for b in CREDENTIAL)),
        modes.CBC(hashlib.md5(name + iviv).digest()),
    ).encryptor()
    sinf = atom(
        b"sinf",
        atom(
            b"schi",
            b"".join(
                (
                    atom(b"name", name),
                    atom(b"iviv", iviv),
                    atom(b"priv", wrapping.update(bytes(clear)) + wrapping.finalize()),
                )
            ),
        ),
    )
    record = b"r" * 16 + b"v" * 16
    encryptor = Cipher(
        algorithms.AES(derive_page_key(record[:16], 1, work)),
        modes.CBC(record[16:]),
    ).encryptor()
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, ARM64, 0, 2, 1, 24, 0, 0)
    command = struct.pack("<IIIIII", 0x2C, 24, 4096, 4096, 1, 0)
    binary = (header + command).ljust(4096, b"\0")
    binary += encryptor.update(PLAINTEXT) + encryptor.finalize()
    architecture = struct.pack(">II", ARM64, 0) + bytes(20) + struct.pack(">I", 1)
    supf = b"\x03507" + bytes(4) + struct.pack(">I", 1)
    supf += struct.pack(">I", len(architecture) + len(record)) + architecture + record
    with ZipFile(path, "w") as archive:
        archive.writestr("Payload/Test.app/Test", binary)
        archive.writestr("Payload/Test.app/SC_Info/Test.sinf", sinf)
        archive.writestr("Payload/Test.app/SC_Info/Test.supf", supf)
        archive.writestr("Payload/Test.app/resource.txt", "preserve me")


class RegionCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ipa = self.root / "input.ipa"
        self.output = self.root / "output.ipa"
        self.store = self.root / "credentials"
        make_ipa(self.ipa)
        self.save("us", "appstore", CREDENTIAL)
        self.save("gb", "appstore", b"x" * 16)
        self.save("us", "arcade", b"y" * 16)

    def save(self, region: str, kind: str, credential: bytes) -> Path:
        path = self.store / region / kind / "credential.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(credential)
        return path

    def run_cli(self, *options: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "decrypt.py"),
                str(self.ipa),
                str(self.output),
                *options,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def region_cli(
        self, region: str, *options: str
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "--region", region, "--credentials-dir", str(self.store), *options
        )

    def test_region_decrypts_and_preserves_other_members(self) -> None:
        result = self.region_cli("US")
        self.assertEqual(result.returncode, 0, result.stderr)
        with ZipFile(self.output) as archive:
            binary = archive.read("Payload/Test.app/Test")
            self.assertEqual(binary[4096:], PLAINTEXT)
            self.assertEqual(struct.unpack_from("<I", binary, 48)[0], 0)
            self.assertEqual(
                archive.read("Payload/Test.app/resource.txt"), b"preserve me"
            )

    def test_wrong_region_never_tries_another_credential(self) -> None:
        result = self.region_cli("gb")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credential does not decode", result.stderr)
        self.assertFalse(self.output.exists())

    def test_missing_region_never_falls_back(self) -> None:
        result = self.region_cli("de")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credential file missing", result.stderr)
        self.assertFalse(self.output.exists())

    def test_arcade_uses_its_own_path(self) -> None:
        result = self.region_cli("us", "--credential-type", "arcade")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credential does not decode", result.stderr)
        self.save("us", "arcade", CREDENTIAL)
        result = self.region_cli("us", "--credential-type", "arcade")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_credential_is_compatible(self) -> None:
        path = self.store / "us" / "appstore" / "credential.bin"
        result = self.run_cli("--credential", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_region_cannot_be_a_path(self) -> None:
        result = self.region_cli("../us")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("two-letter code", result.stderr)

    def test_ambiguous_selection_is_rejected(self) -> None:
        path = self.store / "us" / "appstore" / "credential.bin"
        result = self.region_cli("us", "--credential", str(path))
        self.assertNotEqual(result.returncode, 0)
        result = self.run_cli("--credentials-dir", str(self.store))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require --region", result.stderr)

    def test_invalid_credential_length_is_rejected(self) -> None:
        self.save("us", "appstore", b"short")
        result = self.region_cli("us")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly 16 bytes", result.stderr)


if __name__ == "__main__":
    unittest.main()
