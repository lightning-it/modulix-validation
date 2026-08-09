#!/usr/bin/env python3
"""Render a complete, deliberately non-approved gate-manifest skeleton."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "wunderbox" / "root-of-trust-policy.json"
TEMPLATE_PATH = ROOT / "policies" / "wunderbox" / "gate-manifest.template.json"


def render() -> dict:
    policy_bytes = POLICY_PATH.read_bytes()
    policy = json.loads(policy_bytes)
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    authorization_template = template["authorizations"].pop(
        "REPLACE_WITH_EACH_POLICY_ACTION_ID"
    )
    template["policy_sha256"] = hashlib.sha256(policy_bytes).hexdigest()
    template["authorizations"] = {}
    for action_id, action in policy["actions"].items():
        authorization = copy.deepcopy(authorization_template)
        if action.get("implementation_status", "ready") != "ready":
            authorization["implementation_status"] = "BLOCKED"
            authorization["implementation_blocker"] = action[
                "implementation_blocker"
            ]
        template["authorizations"][action_id] = authorization
    return template


def main() -> int:
    print(json.dumps(render(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
