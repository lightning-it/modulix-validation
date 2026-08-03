#!/usr/bin/env python3
"""Validate the release-publisher jobs in the fetched container workflow."""

from __future__ import annotations

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
REQUIRED_JOBS = (
    "build",
    "upload-trivy-sarif",
    "attach-release-evidence",
)
PUBLISHER_NEEDS = ["build", "upload-trivy-sarif"]


class StrictWorkflowLoader(yaml.SafeLoader):
    """SafeLoader with GitHub-compatible booleans and unique string keys."""


# PyYAML defaults to YAML 1.1, where unquoted ``on`` and ``off`` are booleans.
# GitHub Actions treats them as strings and recognizes only true/false as
# booleans. Copy the resolver table so this loader does not mutate SafeLoader.
StrictWorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)
for resolver_key, resolvers in StrictWorkflowLoader.yaml_implicit_resolvers.items():
    StrictWorkflowLoader.yaml_implicit_resolvers[resolver_key] = [
        resolver
        for resolver in resolvers
        if resolver[0] != "tag:yaml.org,2002:bool"
    ]
StrictWorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def construct_unique_mapping(
    loader: StrictWorkflowLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[str, Any]:
    """Construct a mapping while rejecting duplicate and non-string keys."""

    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a mapping", node.start_mark)

    # Resolve YAML merge keys before checking uniqueness. This deliberately
    # rejects both literal duplicates and aliases that merge colliding keys.
    loader.flatten_mapping(node)
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "workflow mapping keys must be strings",
                key_node.start_mark,
            )
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "workflow mapping keys must be unique",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictWorkflowLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def reject_yaml_graph_features(source: str) -> None:
    """Reject graph expansion syntax before constructing any YAML objects."""

    token_count = 0
    for token in yaml.scan(source, Loader=StrictWorkflowLoader):
        token_count += 1
        if token_count > MAX_YAML_TOKENS:
            raise ValueError("workflow YAML token count exceeds the accepted bound")
        if isinstance(token, (AnchorToken, AliasToken)):
            raise ValueError("workflow YAML anchors and aliases are forbidden")
        if isinstance(token, TagToken):
            raise ValueError("workflow YAML explicit tags are forbidden")
        if (
            isinstance(token, ScalarToken)
            and token.style is None
            and token.value == "<<"
        ):
            raise ValueError("workflow YAML merge keys are forbidden")


def read_bounded_regular_file(path: Path) -> str:
    """Read one regular file without following a final-component symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("workflow is not a regular file")
        if metadata.st_size <= 0 or metadata.st_size > MAX_WORKFLOW_BYTES:
            raise ValueError("workflow size is outside the accepted bound")
        content = bytearray()
        while len(content) <= MAX_WORKFLOW_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_WORKFLOW_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != metadata.st_size or len(content) > MAX_WORKFLOW_BYTES:
            raise ValueError("workflow changed while being read")
        return bytes(content).decode("utf-8")
    finally:
        os.close(descriptor)


def validate_workflow(document: Any) -> None:
    """Require the exact publisher dependency and fail-closed job semantics."""

    if not isinstance(document, dict):
        raise ValueError("workflow root must be a mapping")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        raise ValueError("jobs must be a mapping")

    required: dict[str, dict[str, Any]] = {}
    for job_name in REQUIRED_JOBS:
        job = jobs.get(job_name)
        if not isinstance(job, dict):
            raise ValueError(f"{job_name} must be one job mapping")
        required[job_name] = job

    publisher = required["attach-release-evidence"]
    needs = publisher.get("needs")
    if (
        not isinstance(needs, list)
        or len(needs) != len(PUBLISHER_NEEDS)
        or any(not isinstance(dependency, str) for dependency in needs)
        or needs != PUBLISHER_NEEDS
    ):
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
        document = yaml.load(source, Loader=StrictWorkflowLoader)
        validate_workflow(document)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
