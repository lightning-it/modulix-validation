#!/usr/bin/env python3
"""Repository quality checks for the Lightning IT release model."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path.cwd()
GENERATED = [ROOT / "README.md", ROOT / "RELEASE.md", ROOT / "TESTING.md", ROOT / "OPENSSF.md"]
BEGIN = "<!-- BEGIN LIT_SHARED_RELEASE_MODEL -->"
END = "<!-- END LIT_SHARED_RELEASE_MODEL -->"
QUALITY_BEGIN = "<!-- BEGIN LIT_QUALITY_BADGES -->"
QUALITY_END = "<!-- END LIT_QUALITY_BADGES -->"
MANAGED_BY = "lightning-it/shared-assets-lit"
LICENSE_HEADERS = {
    "MIT": "MIT License",
    "GPL-3.0-only": "GNU GENERAL PUBLIC LICENSE",
    "GPL-3.0-or-later": "GNU GENERAL PUBLIC LICENSE",
}
INVALID_BADGE_VALUES = re.compile(r"(container\s+\(?none\)?|\((?:none|null|undefined)\)|\bundefined\b|\bnull\b)", re.I)
QUAY_STATUS_URL = re.compile(
    r"https?://quay\.io/repository/"
    r"[^/\s)\]}>\"'<]+/[^/\s)\]}>\"'<]+/status"
    r"(?:[/?#][^\s)\]}>\"'<]*)?",
    re.IGNORECASE,
)


def metadata() -> dict[str, str]:
    path = ROOT / ".lit" / "repository.yml"
    if not path.exists():
        raise AssertionError(".lit/repository.yml is missing")
    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line or line.startswith((" ", "-")):
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip("'\"")
    return data


def run(command: list[str], *, required: bool = True) -> None:
    if not required and not shutil_which(command[0]):
        print(f"Skipping {' '.join(command)}: {command[0]} is not installed")
        return
    print("+ " + " ".join(command))
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, command)


def shutil_which(command: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / command
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def assert_file(path: Path) -> str:
    if not path.exists():
        raise AssertionError(f"{path.relative_to(ROOT)} is missing")
    return path.read_text(encoding="utf-8")


def managed_readme_block(readme: str) -> str:
    start = readme.find(BEGIN)
    end = readme.find(END)
    if start == -1 or end == -1 or end < start:
        raise AssertionError("README.md is missing the managed release-model block")
    return readme[start : end + len(END)]


def quality_badge_block(readme: str) -> str:
    start = readme.find(QUALITY_BEGIN)
    end = readme.find(QUALITY_END)
    if start == -1 or end == -1 or end < start:
        raise AssertionError("README.md is missing the managed quality badge block")
    return readme[start : end + len(QUALITY_END)]


def check_quality_badge_block(badge_block: str) -> None:
    if QUAY_STATUS_URL.search(badge_block):
        raise AssertionError("README.md uses Quay status badge endpoint")
    if INVALID_BADGE_VALUES.search(badge_block):
        raise AssertionError("README.md quality badge block contains invalid placeholder value")


def check_generated_docs(meta: dict[str, str]) -> None:
    readme = assert_file(ROOT / "README.md")
    release = assert_file(ROOT / "RELEASE.md")
    testing = assert_file(ROOT / "TESTING.md")
    openssf = assert_file(ROOT / "OPENSSF.md")
    badge_block = quality_badge_block(readme)
    assert_file(ROOT / ".lit" / "repository.yml")
    license_spdx = meta.get("license_spdx", "MIT")

    if meta.get("managed_by") != MANAGED_BY:
        raise AssertionError(f".lit/repository.yml managed_by must be {MANAGED_BY}")

    if BEGIN not in readme or END not in readme:
        raise AssertionError("README.md is missing the managed release-model block")
    if QUALITY_BEGIN not in readme or QUALITY_END not in readme:
        raise AssertionError("README.md is missing the managed quality badge block")
    if "[RELEASE.md](./RELEASE.md)" not in readme:
        raise AssertionError("README.md does not link to RELEASE.md")
    if "## Supported and Tested Platforms" not in readme:
        raise AssertionError("README.md does not include the supported/tested platforms matrix")
    for term in ["Production Ready", "Enterprise Ready", "Battle Tested", "100% Tested", "github/stars", "github/forks"]:
        if term in readme:
            raise AssertionError(f"README.md contains disallowed badge term {term}")
    if meta.get("repository_type", "") not in release:
        raise AssertionError("RELEASE.md does not include the repository type")
    if "Release Evidence" not in release:
        raise AssertionError("RELEASE.md does not describe release evidence")
    if meta.get("repository_type", "") == "container_image":
        for asset in [
            "release-evidence.json",
            "release-evidence.md",
            "release-provenance.intoto.jsonl",
            "sbom.cdx.json",
            "SHA256SUMS",
            "SHA256SUMS.sigstore.json",
        ]:
            if f"`{asset}`" not in release:
                raise AssertionError(f"RELEASE.md does not list required release asset {asset}")
    if "Test Profiles" not in testing:
        raise AssertionError("TESTING.md does not describe test profiles")
    for term in ["OpenSSF Readiness", "Scorecard", "Best Practices Badge", "Security Policy"]:
        if term not in openssf:
            raise AssertionError(f"OPENSSF.md does not include {term}")

    placeholder = re.compile(r"(TODO|TBD|PLACEHOLDER|FIXME)", re.IGNORECASE)
    generated_texts = [
        ("README.md managed block", managed_readme_block(readme)),
        ("README.md quality badge block", badge_block),
        ("RELEASE.md", release),
        ("TESTING.md", testing),
        ("OPENSSF.md", openssf),
    ]
    for label, text in generated_texts:
        if placeholder.search(text):
            raise AssertionError(f"{label} contains unresolved placeholder text")
    check_quality_badge_block(badge_block)

    if "License-MIT" in readme and license_spdx != "MIT":
        raise AssertionError(f"README.md has MIT badge but license_spdx is {license_spdx}")
    if "License-MIT" in readme and not (ROOT / "LICENSE").exists():
        raise AssertionError("README.md has a license badge but no root LICENSE")
    if (ROOT / "LICENSE").exists():
        expected_header = LICENSE_HEADERS.get(license_spdx)
        if expected_header and expected_header not in (ROOT / "LICENSE").read_text(encoding="utf-8")[:200]:
            raise AssertionError(f"LICENSE content does not match {license_spdx}")


def check_secret_safe_generated_docs() -> None:
    secret_patterns = [
        re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
    ]
    readme = assert_file(ROOT / "README.md")
    generated_texts = [
        ("README.md managed block", managed_readme_block(readme)),
        ("RELEASE.md", assert_file(ROOT / "RELEASE.md")),
        ("TESTING.md", assert_file(ROOT / "TESTING.md")),
        ("OPENSSF.md", assert_file(ROOT / "OPENSSF.md")),
        (".lit/repository.yml", assert_file(ROOT / ".lit" / "repository.yml")),
    ]
    for label, text in generated_texts:
        for pattern in secret_patterns:
            if pattern.search(text):
                raise AssertionError(f"{label} appears to contain secret-like material")


def check_terraform(repo_type: str) -> None:
    if repo_type not in {"terraform_module", "terraform_policy"}:
        return
    tf_files = sorted(
        path
        for path in ROOT.glob("**/*.tf")
        if ".terraform" not in path.relative_to(ROOT).parts
    )
    if not tf_files:
        raise AssertionError(
            "Terraform repository has no *.tf files outside .terraform directories"
        )
    if repo_type == "terraform_module" and not any(path.parent == ROOT for path in tf_files):
        raise AssertionError("Terraform module repository has no root *.tf files")
    if shutil_which("terraform"):
        if repo_type == "terraform_module":
            validation_roots = [ROOT]
        else:
            validation_roots = sorted(
                {
                    path.parent
                    for path in tf_files
                    if (path.parent / ".terraform.lock.hcl").is_file()
                    or (path.parent / "versions.tf").is_file()
                    or (path.parent / "backend.tf").is_file()
                }
            )
            if not validation_roots:
                raise AssertionError(
                    "Terraform policy repository has no explicit validation root; "
                    "add .terraform.lock.hcl, versions.tf, or backend.tf"
                )
        # The canonical profile runs inside a read-only source checkout.
        # Terraform writes both .terraform data and dependency lock-file
        # updates below each validation root, so validate one temporary copy
        # instead of allowing writes to the repository. The managed Devtool
        # mounts HOME as a fresh executable tmpfs because downloaded provider
        # binaries must be executable during validate.
        terraform_home = os.environ.get("HOME", "")
        terraform_temp_parent = Path(terraform_home)
        resolved_temp_parent = (
            terraform_temp_parent.resolve()
            if terraform_home and terraform_temp_parent.is_absolute()
            else terraform_temp_parent
        )
        resolved_root = ROOT.resolve()
        if (
            not terraform_home
            or not terraform_temp_parent.is_absolute()
            or not terraform_temp_parent.is_dir()
            or terraform_temp_parent.is_symlink()
            or resolved_temp_parent == resolved_root
            or resolved_root in resolved_temp_parent.parents
        ):
            raise AssertionError(
                "Terraform validation requires an absolute, existing, "
                "non-symlink HOME outside the repository for executable "
                "temporary data"
            )
        with tempfile.TemporaryDirectory(
            prefix="lit-terraform-",
            dir=resolved_temp_parent,
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            workspace = temporary_root / "workspace"
            data_root = temporary_root / "data"
            shutil.copytree(
                ROOT,
                workspace,
                symlinks=True,
                ignore=shutil.ignore_patterns(".git", ".terraform"),
            )
            for current_root, directory_names, file_names in os.walk(
                workspace,
                followlinks=False,
            ):
                current_path = Path(current_root)
                for name in (*directory_names, *file_names):
                    candidate = current_path / name
                    if candidate.is_symlink():
                        raise AssertionError(
                            "Terraform validation workspace may not contain "
                            f"symlinks: {candidate.relative_to(workspace)}"
                        )
            run(
                [
                    "terraform",
                    f"-chdir={workspace}",
                    "fmt",
                    "-check",
                    "-recursive",
                ]
            )
            data_root.mkdir()
            previous_data_dir = os.environ.get("TF_DATA_DIR")
            try:
                for root_index, validation_root in enumerate(validation_roots):
                    relative_root = validation_root.relative_to(ROOT)
                    data_dir = data_root / f"{root_index:04d}"
                    data_dir.mkdir()
                    validation_copy = workspace / relative_root
                    resolved_workspace = workspace.resolve()
                    resolved_validation_copy = validation_copy.resolve()
                    lock_file = validation_copy / ".terraform.lock.hcl"
                    if (
                        resolved_validation_copy != resolved_workspace
                        and resolved_workspace not in resolved_validation_copy.parents
                    ) or validation_copy.is_symlink() or not validation_copy.is_dir() or (
                        lock_file.exists() and not lock_file.is_file()
                    ):
                        raise AssertionError(
                            "Terraform validation copy must resolve inside its temporary "
                            "workspace and use a regular dependency lock file"
                        )
                    os.environ["TF_DATA_DIR"] = str(data_dir)
                    run(
                        [
                            "terraform",
                            f"-chdir={validation_copy}",
                            "init",
                            "-backend=false",
                            "-input=false",
                        ]
                    )
                    run(
                        [
                            "terraform",
                            f"-chdir={validation_copy}",
                            "validate",
                            "-no-color",
                        ]
                    )
            finally:
                if previous_data_dir is None:
                    os.environ.pop("TF_DATA_DIR", None)
                else:
                    os.environ["TF_DATA_DIR"] = previous_data_dir
    else:
        print("Terraform CLI not installed; checked Terraform file presence only")


def check_helm(repo_type: str) -> None:
    if repo_type != "helm_chart":
        return
    chart_files = sorted(ROOT.glob("**/Chart.yaml"))
    if not chart_files:
        print("No Chart.yaml files found; treating repository as chart placeholder")
        return
    if shutil_which("helm"):
        for chart in chart_files:
            run(["helm", "lint", str(chart.parent)])
            run(["helm", "template", "lit-quality", str(chart.parent)])
    else:
        print("Helm CLI not installed; checked Chart.yaml presence only")


def check_packer(repo_type: str) -> None:
    if repo_type != "packer_template":
        return
    pkr_files = sorted(ROOT.glob("*.pkr.hcl"))
    if not pkr_files:
        print("No root *.pkr.hcl files found; treating repository as template placeholder")
        return
    if shutil_which("packer"):
        run(["packer", "fmt", "-check", "."])
        run(["packer", "validate", "-syntax-only", "."])
    else:
        print("Packer CLI not installed; checked Packer file presence only")


def check_markdown() -> None:
    for path in GENERATED:
        text = assert_file(path)
        if "\t" in text:
            raise AssertionError(f"{path.name} contains tab characters")
        if not text.endswith("\n"):
            raise AssertionError(f"{path.name} must end with a newline")


def check_embedded_code() -> None:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT}", "ls-files", "-z"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        capture_output=True,
        check=False,
    )
    if result.returncode:
        details = result.stderr.strip()
        raise AssertionError(
            "cannot enumerate tracked Markdown files with git ls-files"
            + (f": {details}" if details else "")
        )
    markdown_paths = sorted(
        path
        for path in result.stdout.split("\0")
        if path and Path(path).suffix.lower() == ".md"
    )
    if markdown_paths:
        validator = ROOT / "scripts" / "validate-embedded-code.py"
        shared_validator = ROOT / "default" / "scripts" / "validate-embedded-code.py"
        if not validator.is_file() and shared_validator.is_file():
            validator = shared_validator
        command_prefix = [
            sys.executable,
            validator.relative_to(ROOT).as_posix(),
        ]
        batch: list[str] = []
        batch_bytes = 0
        for path in markdown_paths:
            path_bytes = len(os.fsencode(path)) + 1
            if batch and (len(batch) >= 100 or batch_bytes + path_bytes > 60_000):
                run([*command_prefix, *batch])
                batch = []
                batch_bytes = 0
            batch.append(path)
            batch_bytes += path_bytes
        if batch:
            run([*command_prefix, *batch])


def check_managed_assets() -> None:
    """Verify the optional repository-specific provenance inventory."""
    inventory_path = ROOT / ".lit" / "managed-assets.json"
    if not inventory_path.exists():
        return
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssertionError(
            f".lit/managed-assets.json cannot be read as JSON: {exc}"
        ) from exc
    if not isinstance(inventory, dict):
        raise AssertionError(".lit/managed-assets.json root must be an object")
    if inventory.get("schema_version") != 1:
        raise AssertionError(".lit/managed-assets.json schema_version must be 1")
    assets = inventory.get("assets")
    if not isinstance(assets, list):
        raise AssertionError(".lit/managed-assets.json assets must be a list")

    seen: set[str] = set()
    allowed = {
        "central-managed",
        "local-required",
        "private-configuration",
    }
    for asset in assets:
        if not isinstance(asset, dict):
            raise AssertionError("managed asset entries must be objects")
        path_text = asset.get("path", "")
        category = asset.get("category", "")
        if not isinstance(path_text, str) or not path_text:
            raise AssertionError(f"managed asset path must be a non-empty string: {path_text!r}")
        if not isinstance(category, str):
            raise AssertionError(f"{path_text}: managed asset category must be a string")
        relative_path = Path(path_text)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise AssertionError(f"{path_text}: managed asset path must be repository-relative")
        normalized_path = relative_path.as_posix()
        if normalized_path in {"", "."} or normalized_path != path_text:
            raise AssertionError(f"{path_text}: managed asset path must be normalized")
        if normalized_path in seen:
            raise AssertionError(f"managed asset path is duplicated: {normalized_path!r}")
        seen.add(normalized_path)
        if category not in allowed:
            raise AssertionError(f"{path_text}: invalid managed asset category {category!r}")
        path = ROOT / normalized_path
        if path.is_symlink():
            raise AssertionError(f"{path_text}: inventoried assets may not be symlinks")
        if not path.is_file():
            raise AssertionError(f"{path_text}: inventoried asset is missing")
        if category == "central-managed":
            source = asset.get("source")
            if not isinstance(source, str) or not source.strip():
                raise AssertionError(f"{path_text}: central-managed asset has no source")
            expected_digest = asset.get("sha256")
            if not isinstance(expected_digest, str) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_digest
            ):
                raise AssertionError(
                    f"{path_text}: central-managed sha256 must be 64 lowercase hex characters"
                )
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != expected_digest:
                raise AssertionError(
                    f"{path_text}: unsupported local drift from centrally managed source"
                )
        elif category in {"local-required", "private-configuration"}:
            purpose = asset.get("purpose")
            owner = asset.get("owner")
            if (
                not isinstance(purpose, str)
                or not purpose.strip()
                or not isinstance(owner, str)
                or not owner.strip()
            ):
                raise AssertionError(f"{path_text}: local asset needs purpose and owner")

    try:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
        ).stdout.split("\0")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AssertionError(
            "managed asset inventory requires a readable Git worktree"
        ) from exc
    ignored_prefixes = ("docs/", "dist/")
    current = {
        path_text
        for path_text in tracked
        if path_text
        and path_text != inventory_path.relative_to(ROOT).as_posix()
        and not path_text.startswith(ignored_prefixes)
        and "__pycache__" not in Path(path_text).parts
        and not path_text.endswith(".pyc")
    }
    missing = sorted(current - seen)
    stale = sorted(seen - current)
    if missing:
        raise AssertionError(f"non-doc assets missing from provenance inventory: {', '.join(missing)}")
    if stale:
        raise AssertionError(f"stale provenance inventory entries: {', '.join(stale)}")


def check_pge_confluence_conformance_assets() -> None:
    """Keep the governed documentation validator bound to reviewed assets."""
    required_paths = [
        ROOT / ".github" / "scripts" / "pge-confluence-conformance.py",
        ROOT / ".github" / "workflows" / "pge-confluence-conformance.yml",
        ROOT / "inventories" / "pge" / "confluence-conformance.json",
        ROOT / "docs" / "pge-confluence-conformance.md",
        ROOT / "tests" / "test_pge_confluence_conformance.py",
        ROOT / "tests" / "test_pge_confluence_workflow.py",
    ]
    for path in required_paths:
        if path.is_symlink() or not path.is_file():
            raise AssertionError(
                "PGE Confluence conformance asset is missing or not a regular file: "
                f"{path.relative_to(ROOT)}"
            )

    config_path = ROOT / "inventories" / "pge" / "confluence-conformance.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssertionError("PGE Confluence target inventory is invalid JSON") from exc
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise AssertionError("PGE Confluence target inventory schema_version must be 1")
    if config.get("allowed_confluence_origin") != "https://wiki.cloud.l-it.io":
        raise AssertionError(
            "PGE Confluence target inventory must remain bound to the reviewed origin"
        )
    targets = config.get("targets")
    if not isinstance(targets, list) or not targets:
        raise AssertionError("PGE Confluence target inventory needs targets")
    names: set[str] = set()
    roots: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise AssertionError("PGE Confluence targets must be objects")
        name = target.get("name")
        root_page_id = target.get("root_page_id")
        profile = target.get("profile")
        traversal = target.get("traversal")
        expected_page_count = target.get("expected_page_count")
        excluded_roots = target.get("excluded_subtree_root_ids", [])
        exclusion_authorities = target.get("exclusion_authorities", [])
        delegated_subtrees = target.get("delegated_subtree_targets", [])
        classification_counts = target.get("expected_classification_counts")
        expected_count_is_valid = expected_page_count is None or (
            isinstance(expected_page_count, int)
            and not isinstance(expected_page_count, bool)
            and expected_page_count > 0
        )
        excluded_roots_are_valid = (
            isinstance(excluded_roots, list)
            and all(isinstance(value, str) and value.isdigit() for value in excluded_roots)
            and len(excluded_roots) == len(set(excluded_roots))
            and root_page_id not in excluded_roots
        )
        authority_ids = (
            [value.get("page_id") for value in exclusion_authorities]
            if isinstance(exclusion_authorities, list)
            and all(isinstance(value, dict) for value in exclusion_authorities)
            else []
        )
        exclusion_authorities_are_valid = (
            isinstance(exclusion_authorities, list)
            and all(
                isinstance(value, dict)
                and set(value) == {"page_id", "version"}
                and isinstance(value.get("page_id"), str)
                and value["page_id"].isdigit()
                and isinstance(value.get("version"), int)
                and not isinstance(value["version"], bool)
                and value["version"] > 0
                for value in exclusion_authorities
            )
            and len(authority_ids) == len(set(authority_ids))
        )
        delegated_roots = (
            [value.get("root_page_id") for value in delegated_subtrees]
            if isinstance(delegated_subtrees, list)
            and all(isinstance(value, dict) for value in delegated_subtrees)
            else []
        )
        delegated_subtrees_are_valid = (
            isinstance(delegated_subtrees, list)
            and all(
                isinstance(value, dict)
                and set(value) == {"root_page_id", "target_name"}
                and isinstance(value.get("root_page_id"), str)
                and value["root_page_id"].isdigit()
                and isinstance(value.get("target_name"), str)
                and bool(value["target_name"])
                and value["target_name"] != name
                for value in delegated_subtrees
            )
            and len(delegated_roots) == len(set(delegated_roots))
        )
        classification_counts_are_valid = classification_counts is None or (
            isinstance(classification_counts, dict)
            and set(classification_counts)
            == {"direct_validated", "delegated", "disposition_excluded"}
            and all(
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
                for value in classification_counts.values()
            )
            and expected_page_count is not None
            and sum(classification_counts.values()) == expected_page_count
        )
        if (
            not isinstance(name, str)
            or not name
            or name in names
            or not isinstance(root_page_id, str)
            or not root_page_id.isdigit()
            or root_page_id in roots
            or profile not in {"product", "template", "engagement"}
            or traversal not in {"recursive", "page-only"}
            or not expected_count_is_valid
            or not excluded_roots_are_valid
            or not exclusion_authorities_are_valid
            or not delegated_subtrees_are_valid
            or not classification_counts_are_valid
            or bool(excluded_roots) != bool(exclusion_authorities)
            or (excluded_roots and traversal != "recursive")
            or (delegated_subtrees and traversal != "recursive")
            or any(authority_id in excluded_roots for authority_id in authority_ids)
            or root_page_id in delegated_roots
            or any(root_id in excluded_roots for root_id in delegated_roots)
            or (expected_page_count is None and not excluded_roots)
        ):
            raise AssertionError("PGE Confluence target inventory contains an invalid target")
        names.add(name)
        roots.add(root_page_id)
    targets_by_name = {target["name"]: target for target in targets}
    for target in targets:
        for delegation in target.get("delegated_subtree_targets", []):
            delegated_target = targets_by_name.get(delegation["target_name"])
            if (
                delegated_target is None
                or delegated_target.get("root_page_id") != delegation["root_page_id"]
            ):
                raise AssertionError(
                    "PGE Confluence delegated subtree does not match its covering target"
                )
    canonical_targets = [
        target for target in targets if target.get("name") == "pge-canonical-product"
    ]
    if len(canonical_targets) != 1:
        raise AssertionError("PGE Confluence inventory needs the canonical product target")
    canonical = canonical_targets[0]
    if (
        canonical.get("root_page_id") != "2875654145"
        or canonical.get("expected_page_count") != 792
        or len(canonical.get("excluded_subtree_root_ids", [])) != 69
        or canonical.get("expected_classification_counts")
        != {
            "direct_validated": 52,
            "delegated": 51,
            "disposition_excluded": 689,
        }
        or {
            (authority.get("page_id"), authority.get("version"))
            for authority in canonical.get("exclusion_authorities", [])
        }
        != {("2892759041", 12), ("2892890133", 10)}
        or canonical.get("delegated_subtree_targets")
        != [
            {
                "root_page_id": "2882765966",
                "target_name": "pge-product-decisions",
            },
            {
                "root_page_id": "2891710468",
                "target_name": "pge-template-library",
            },
        ]
    ):
        raise AssertionError(
            "PGE canonical product scope or exclusion authority versions changed"
        )
    for alignment in config.get("alignments", []):
        product_sources = (
            alignment.get("product_source_artifacts")
            if isinstance(alignment, dict)
            else None
        )
        if (
            not isinstance(alignment, dict)
            or not isinstance(alignment.get("name"), str)
            or not alignment["name"]
            or alignment.get("template_target") not in names
            or alignment.get("catalog_target") not in names
            or alignment.get("template_target") == alignment.get("catalog_target")
            or not isinstance(product_sources, list)
            or any(
                not isinstance(value, str) or not value.strip()
                for value in product_sources
            )
            or len(product_sources) != len(set(product_sources))
        ):
            raise AssertionError("PGE Confluence target inventory contains an invalid alignment")

    workflow = assert_file(
        ROOT / ".github" / "workflows" / "pge-confluence-conformance.yml"
    )
    for contract in (
        "workflow_dispatch:",
        "pge-confluence-read-only",
        "pge-canonical-product",
        "pge-product-baseline)",
        "--target pge-product-decisions",
        "--target pge-template-library",
        "--target pge-artifact-catalog",
        'test "${GITHUB_REF}" = "refs/heads/main"',
        "--redact-details",
        "PGE_CONFLUENCE_API_TOKEN: ${{ secrets.PGE_CONFLUENCE_API_TOKEN }}",
    ):
        if contract not in workflow:
            raise AssertionError(
                f"PGE Confluence workflow is missing protected contract {contract!r}"
            )
    if "--snapshot-out" in workflow:
        raise AssertionError("PGE Confluence workflow must not upload live snapshots")
    if workflow.count("secrets.PGE_CONFLUENCE_") != 2:
        raise AssertionError("PGE Confluence secrets must appear only in the audit step")

    readme = assert_file(ROOT / "README.md")
    if "docs/pge-confluence-conformance.md" not in readme:
        raise AssertionError("README.md does not link the PGE Confluence validator")
    ignore = assert_file(ROOT / ".gitignore")
    for ignored_path in (".pge-conformance/", "evidence/", "snapshots/"):
        if ignored_path not in ignore.splitlines():
            raise AssertionError(
                f".gitignore does not exclude PGE evidence path {ignored_path}"
            )


def main() -> int:
    try:
        meta = metadata()
        check_generated_docs(meta)
        check_secret_safe_generated_docs()
        check_markdown()
        check_embedded_code()
        check_managed_assets()
        check_pge_confluence_conformance_assets()
        repo_type = meta.get("repository_type", "")
        check_terraform(repo_type)
        check_helm(repo_type)
        check_packer(repo_type)
    except subprocess.CalledProcessError as exc:
        return exc.returncode
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Lightning IT repository quality checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
