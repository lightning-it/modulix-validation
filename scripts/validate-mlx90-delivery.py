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
    if not isinstance(result, dict):
        raise ValueError("acceptance result must be an object")
    if result.get("apiVersion") != "lit.security-release.acceptance/v1":
        raise ValueError("unsupported acceptance version")
    if result.get("status") not in {"delivered", "blocked", "revoked"}:
        raise ValueError("invalid status")
    if result["status"] != "delivered":
        return
    chain = result.get("chain", {})
    checks = result.get("checks", {})
    if not isinstance(chain, dict) or not isinstance(checks, dict):
        raise ValueError("chain and checks must be objects")
    if not isinstance(chain.get("collectionSourceSha"), str) or not SHA.fullmatch(chain["collectionSourceSha"]):
        raise ValueError("missing collection source SHA")
    if not isinstance(chain.get("consumerMergeSha"), str) or not SHA.fullmatch(chain["consumerMergeSha"]):
        raise ValueError("missing consumer merge SHA")
    if not isinstance(chain.get("collectionDigest"), str) or not DIGEST.fullmatch(chain["collectionDigest"]):
        raise ValueError("missing collection digest")
    if not isinstance(chain.get("containerManifestDigest"), str) or not DIGEST.fullmatch(chain["containerManifestDigest"]):
        raise ValueError("missing container manifest digest")
    if set(checks) != REQUIRED or any(value is not True for value in checks.values()):
        raise ValueError("all final digest acceptance checks must be true")
    if not isinstance(chain.get("pulledImage"), str) or not chain["pulledImage"].endswith("@" + chain["containerManifestDigest"]):
        raise ValueError("pulled image is not bound to the accepted manifest digest")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.result.read_text(encoding="utf-8"))
        validate(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(payload["status"])


if __name__ == "__main__":
    main()
