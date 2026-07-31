import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mlx90", ROOT / "scripts/validate-mlx90-delivery.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class DeliveryTests(unittest.TestCase):
    def fixture(self):
        return {"apiVersion": "lit.security-release.acceptance/v1", "status": "delivered", "chain": {"collectionSourceSha": "1" * 40, "collectionDigest": "sha256:" + "a" * 64, "consumerMergeSha": "2" * 40, "containerManifestDigest": "sha256:" + "b" * 64, "pulledImage": "quay.io/lit/ee@sha256:" + "b" * 64}, "checks": {name: True for name in MODULE.REQUIRED}}

    def test_complete_digest_chain_is_delivered(self):
        MODULE.validate(self.fixture())

    def test_pr_success_or_missing_check_cannot_deliver(self):
        for mutation in ("containerManifestDigest", "pulledImage"):
            value = self.fixture(); value["chain"].pop(mutation)
            with self.assertRaises(ValueError): MODULE.validate(value)
        value = self.fixture(); value["checks"]["provenance"] = False
        with self.assertRaises(ValueError): MODULE.validate(value)

    def test_blocked_and_revoked_are_valid_terminal_states(self):
        for state in ("blocked", "revoked"):
            MODULE.validate({"apiVersion": "lit.security-release.acceptance/v1", "status": state})


if __name__ == "__main__": unittest.main()
