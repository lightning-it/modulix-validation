import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mlx90_finalizer",
    ROOT / "scripts" / "finalize-mlx90-delivery.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class FinalizerCoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_profiles_are_allowlisted_and_release_eligible(self):
        profile_id = "lit.supplementary/security-fix-2026-001"
        eligible = {
            "description": "Synthetic test profile.",
            "releaseEligible": True,
            "containerCommand": ["/usr/local/bin/security-fix-check"],
        }
        profiles = {profile_id: eligible}
        self.assertIs(eligible, MODULE.eligible_profile(profiles, profile_id))
        with self.assertRaisesRegex(ValueError, "fixed allowlist"):
            MODULE.eligible_profile(profiles, "lit.supplementary/unknown")
        eligible["releaseEligible"] = False
        with self.assertRaisesRegex(ValueError, "non-releaseable"):
            MODULE.eligible_profile(profiles, profile_id)

    def test_secure_snapshot_is_regular_bounded_stable_and_same_byte(self):
        marker = f"SECRET-SNAPSHOT\n{self.root}"
        first = b'{"source":"first"}\n'
        second = b'{"source":"second"}\n'
        material = self.root / "material.json"
        material.write_bytes(first)
        snapshot = MODULE.secure_file_snapshot(
            material, 1024, capture_payload=True
        )
        replacement = self.root / "replacement.json"
        replacement.write_bytes(second)
        replacement.replace(material)
        self.assertEqual(
            {"source": "first"},
            MODULE.parse_json_snapshot(snapshot, "material"),
        )
        self.assertEqual(digest(first), snapshot.digest)
        self.assertNotEqual(digest(second), snapshot.digest)

        symlink = self.root / "material-link.json"
        symlink.symlink_to(material)
        fifo = self.root / "material.fifo"
        MODULE.os.mkfifo(fifo)
        directory = self.root / "material-directory"
        directory.mkdir()
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"12345")
        for candidate, limit in (
            (symlink, 1024),
            (fifo, 1024),
            (directory, 1024),
            (oversized, 4),
        ):
            with self.subTest(candidate=candidate.name):
                with self.assertRaises(ValueError) as caught:
                    MODULE.secure_file_snapshot(candidate, limit)
                self.assertEqual(
                    MODULE.MATERIAL_FILE_ERROR, str(caught.exception)
                )

        stable = material.stat()
        changed = mock.Mock(
            st_mode=stable.st_mode,
            st_dev=stable.st_dev,
            st_ino=stable.st_ino,
            st_size=stable.st_size,
            st_mtime_ns=stable.st_mtime_ns + 1,
            st_ctime_ns=stable.st_ctime_ns,
        )
        with mock.patch.object(
            MODULE.os, "fstat", side_effect=(stable, changed)
        ):
            with self.assertRaises(ValueError) as caught:
                MODULE.secure_file_snapshot(material, 1024)
        self.assertEqual(MODULE.MATERIAL_FILE_ERROR, str(caught.exception))

        with mock.patch.object(
            MODULE.os, "open", side_effect=OSError(marker)
        ):
            with self.assertRaises(ValueError) as caught:
                MODULE.secure_file_snapshot(material, 1024)
        self.assertEqual(MODULE.MATERIAL_FILE_ERROR, str(caught.exception))
        self.assertNotIn(marker, str(caught.exception))

    def test_raw_index_and_serialized_outputs_bind_exact_bytes(self):
        index_path = self.root / "index.json"
        index_bytes = b'{"schemaVersion":2,"manifests":[]}\n'
        index_path.write_bytes(index_bytes)
        container = {
            "variants": {
                "public": {"manifestDigest": digest(index_bytes)}
            }
        }
        self.assertEqual(
            {"schemaVersion": 2, "manifests": []},
            MODULE.load_verified_index(container, "public", index_path),
        )
        index_path.write_bytes(index_bytes + b" ")
        with self.assertRaisesRegex(ValueError, "raw OCI index digest"):
            MODULE.load_verified_index(container, "public", index_path)

        output = self.root / "output.json"
        expected = b'{\n  "accepted": true\n}\n'
        with mock.patch.object(
            MODULE,
            "file_digest_and_size",
            side_effect=AssertionError("published JSON must not be reopened"),
        ):
            observed_digest, observed_size = MODULE.write_json(
                output, {"accepted": True}
            )
        self.assertEqual(expected, output.read_bytes())
        self.assertEqual(digest(expected), observed_digest)
        self.assertEqual(len(expected), observed_size)
        with self.assertRaisesRegex(ValueError, "output already exists"):
            MODULE.write_json(output, {})
        self.assertEqual(expected, output.read_bytes())

    def test_structural_materials_and_variants_fail_without_value_echo(self):
        marker = f"SECRET-STRUCTURE\n{self.root}"
        missing = self.root / "not-used"
        for identifiers in ([{marker: True}], [[marker]], [marker]):
            with self.assertRaises(ValueError) as caught:
                MODULE.require_security_identifiers(identifiers)
            self.assertEqual(
                "security.identifiers must be a non-empty unique string list",
                str(caught.exception),
            )
            self.assertNotIn(marker, str(caught.exception))
        for producer in ({}, {"artifact": []}):
            with self.assertRaises(ValueError) as caught:
                MODULE.verify_producer_materials(
                    producer, missing, missing, missing
                )
            self.assertNotIn(marker, str(caught.exception))

        target = f"sha256:{'a' * 64}"
        index = {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": (
                        "application/vnd.oci.image.manifest.v1+json"
                    ),
                    "digest": f"sha256:{'b' * 64}",
                    "annotations": {
                        "vnd.docker.reference.digest": target,
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                    "platform": {
                        "os": "unknown",
                        "architecture": "unknown",
                    },
                }
            ],
        }
        for platform_digests in (
            [],
            {"linux/amd64": target},
            {"linux/amd64": marker, "linux/arm64": target},
        ):
            container = {
                "variants": {
                    "public": {"platformDigests": platform_digests}
                }
            }
            with self.subTest(platform_digests=platform_digests):
                with self.assertRaises(ValueError) as caught:
                    MODULE.verify_index(container, "public", index)
                self.assertNotIn(marker, str(caught.exception))

        for action in (
            lambda: MODULE.verify_index({}, marker, {}),
            lambda: MODULE.verify_container_materials(
                {}, marker, missing, missing, missing, missing
            ),
            lambda: MODULE.verify_buildkit_attestations(
                {}, marker, missing, self.root
            ),
        ):
            with self.assertRaises(ValueError) as caught:
                action()
            self.assertNotIn(marker, str(caught.exception))

    def test_all_cli_branches_have_value_free_exception_boundaries(self):
        marker = f"SECRET-CLI\n{self.root}"
        commands = (
            ("validate-inputs", "identity_from_args"),
            ("preflight", "validated_inputs"),
            ("profile-command", "load_profiles"),
            ("verify-producer-materials", "load_json"),
            ("verify-index", "load_json"),
            ("verify-buildkit-attestations", "load_json"),
            ("verify-container-materials", "load_json"),
            ("verify-installed", "load_json"),
            ("write-receipt", "validated_inputs"),
            ("write-report", "validated_inputs"),
            ("finalize", "validated_inputs"),
        )
        arguments = MODULE.argparse.Namespace(
            profiles=self.root / "profiles.json",
            profile="lit.supplementary/profile",
            producer_evidence=self.root / "producer.json",
            container_evidence=self.root / "container.json",
            result=self.root / "result.json",
        )

        class BoundaryError(Exception):
            pass

        def parser_error(message):
            raise BoundaryError(message)

        errors = (
            (KeyError, MODULE.CLI_CONTRACT_ERROR),
            (TypeError, MODULE.CLI_CONTRACT_ERROR),
            (IndexError, MODULE.CLI_CONTRACT_ERROR),
            (OSError, MODULE.CLI_IO_ERROR),
        )
        for command, target in commands:
            arguments.command = command
            for error_type, expected in errors:
                parser = mock.Mock()
                parser.parse_args.return_value = arguments
                parser.error.side_effect = parser_error
                with self.subTest(command=command, error=error_type.__name__):
                    with mock.patch.object(
                        MODULE, "build_parser", return_value=parser
                    ), mock.patch.object(
                        MODULE, target, side_effect=error_type(marker)
                    ):
                        with self.assertRaises(BoundaryError) as caught:
                            MODULE.main()
                self.assertEqual(expected, str(caught.exception))
                self.assertNotIn(marker, str(caught.exception))

        script = str(ROOT / "scripts" / "finalize-mlx90-delivery.py")
        for cli_arguments in (
            ["unknown-" + marker],
            ["validate-inputs", "--consumer-pr", marker],
        ):
            completed = subprocess.run(
                [sys.executable, script, *cli_arguments],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            output = completed.stdout + completed.stderr
            self.assertIn(MODULE.CLI_ARGUMENT_ERROR, output)
            self.assertNotIn(marker, output)
            self.assertNotIn(str(self.root), output)
            self.assertNotIn("Traceback", output)

    def test_receipt_id_is_allowlisted_before_observations_are_loaded(self):
        marker = f"SECRET-RECEIPT\n{self.root}"
        parser = mock.Mock()
        parser.parse_args.return_value = MODULE.argparse.Namespace(
            command="write-receipt",
            receipt_id=marker,
        )
        parser.error.side_effect = ValueError
        with mock.patch.object(
            MODULE, "build_parser", return_value=parser
        ), mock.patch.object(
            MODULE,
            "validated_inputs",
            return_value=(None, None, None, None, None, None),
        ), mock.patch.object(MODULE, "load_json") as loader:
            with self.assertRaises(ValueError) as caught:
                MODULE.main()
        loader.assert_not_called()
        self.assertNotIn(marker, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
