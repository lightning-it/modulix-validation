#!/usr/bin/env python3
"""Cross-repository MLX-90 final-state guard.

Schema validation remains owned by shared-assets. This layer enforces that an
E2E result cannot claim delivery without immutable producer, consumer and
container bindings and successful final verification outcomes.
"""
import argparse
import json
import re
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED = {"pulledByDigest", "collectionVersion", "securityAcceptance", "signature", "sbom", "provenance"}


def validate(result):
    if result.get("apiVersion") != "lit.security-release.acceptance/v1":
        raise ValueError("unsupported acceptance version")
    if result.get("status") not in {"delivered", "blocked", "revoked"}:
        raise ValueError("invalid status")
    if result["status"] != "delivered":
        return
    chain = result.get("chain", {})
    if not SHA.fullmatch(str(chain.get("collectionSourceSha", ""))):
        raise ValueError("missing collection source SHA")
    if not SHA.fullmatch(str(chain.get("consumerMergeSha", ""))):
        raise ValueError("missing consumer merge SHA")
    if not DIGEST.fullmatch(str(chain.get("collectionDigest", ""))):
        raise ValueError("missing collection digest")
    if not DIGEST.fullmatch(str(chain.get("containerManifestDigest", ""))):
        raise ValueError("missing container manifest digest")
    checks = result.get("checks", {})
    if set(checks) != REQUIRED or any(value is not True for value in checks.values()):
        raise ValueError("all final digest acceptance checks must be true")
    if "@" + chain["containerManifestDigest"] not in str(chain.get("pulledImage", "")):
        raise ValueError("pulled image is not bound to the accepted manifest digest")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.result.read_text())
        validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(payload["status"])


if __name__ == "__main__":
    main()
