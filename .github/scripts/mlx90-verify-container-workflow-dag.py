#!/usr/bin/env python3
"""Validate workflow DAG."""

import copy
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.tokens import AliasToken, AnchorToken, ScalarToken, TagToken


MAX_WORKFLOW_BYTES = 1_048_576
MAX_YAML_TOKENS = 50_000
REQUIRED_JOB_NAMES = {
    "build": "Build & push image to Quay.io",
    "upload-trivy-sarif": "Upload Trivy release gate SARIF",
    "attach-release-evidence": "Attach signed release evidence",
}
PUBLISHER_NEEDS = ["build", "upload-trivy-sarif"]


class StrictWorkflowLoader(yaml.SafeLoader):
    pass


# Match GitHub booleans; do not mutate SafeLoader.
StrictWorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers)
for resolver_key, resolvers in StrictWorkflowLoader.yaml_implicit_resolvers.items():
    StrictWorkflowLoader.yaml_implicit_resolvers[resolver_key] = [
        resolver for resolver in resolvers
        if resolver[0] != "tag:yaml.org,2002:bool"]
StrictWorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"))


def construct_unique_mapping(loader, node, deep=False) -> dict[str, Any]:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a mapping", node.start_mark)
    loader.flatten_mapping(node)
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in mapping:
            requirement = "strings" if not isinstance(key, str) else "unique"
            raise ConstructorError("mapping", node.start_mark,
                f"workflow mapping keys must be {requirement}", key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictWorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping)


def reject_yaml_graph_features(source: str) -> None:
    token_count = 0
    for token in yaml.scan(source, Loader=StrictWorkflowLoader):
        token_count += 1
        if token_count > MAX_YAML_TOKENS:
            raise ValueError("too many YAML tokens")
        if (isinstance(token, (AnchorToken, AliasToken, TagToken))
                or isinstance(token, ScalarToken)
                and token.style is None and token.value == "<<"):
            raise ValueError("forbidden YAML graph")


def read_bounded_regular_file(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or not 0 < metadata.st_size <= MAX_WORKFLOW_BYTES):
            raise ValueError("invalid workflow file")
        content = bytearray()
        while len(content) <= MAX_WORKFLOW_BYTES:
            chunk = os.read(descriptor,
                min(65_536, MAX_WORKFLOW_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != metadata.st_size or len(content) > MAX_WORKFLOW_BYTES:
            raise ValueError("workflow changed")
        return bytes(content).decode("utf-8")
    finally:
        os.close(descriptor)


def validate_workflow(document: Any) -> None:
    if not isinstance(document, dict):
        raise ValueError("workflow root must be a mapping")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        raise ValueError("jobs must be a mapping")

    required: dict[str, dict[str, Any]] = {}
    for job_name, display_name in REQUIRED_JOB_NAMES.items():
        job = jobs.get(job_name)
        if not isinstance(job, dict):
            raise ValueError(f"{job_name} must be one job mapping")
        owners = sum(isinstance(candidate, dict)
            and candidate.get("name") == display_name
            for candidate in jobs.values())
        if job.get("name") != display_name or owners != 1:
            raise ValueError(f"{job_name} display name must be exact and unique")
        required[job_name] = job

    publisher = required["attach-release-evidence"]
    if publisher.get("needs") != PUBLISHER_NEEDS:
        raise ValueError("publisher needs must be the exact ordered job list")
    if "if" in publisher:
        raise ValueError("publisher must retain default success semantics")

    for job_name, job in required.items():
        if "continue-on-error" in job:
            raise ValueError(f"{job_name} must fail closed")


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        return 2
    try:
        source = read_bounded_regular_file(Path(arguments[1]))
        reject_yaml_graph_features(source)
        validate_workflow(yaml.load(source, Loader=StrictWorkflowLoader))
    except (OSError, UnicodeError, ValueError, yaml.YAMLError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
