#!/usr/bin/env python3
"""Fail-closed Confluence documentation conformance validation for PGE trees.

The live mode is strictly read-only.  It retrieves explicitly configured page
trees from Confluence Cloud REST API v2 and emits sanitized evidence reports.
The snapshot mode validates the exact same input without network access.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Iterable, Sequence
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


SNAPSHOT_SCHEMA_VERSION = 2
REPORT_SCHEMA_VERSION = 2
DEFAULT_MAX_PAGES = 5_000
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_ALLOWED_CONFLUENCE_ORIGIN = "https://wiki.cloud.l-it.io"
ALLOWED_PROFILES = {"product", "template", "engagement"}
ALLOWED_TRAVERSAL_MODES = {"recursive", "page-only"}
ALLOWED_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
ALLOWED_STATUSES = {
    "accepted",
    "accepted with conditions",
    "active",
    "approved",
    "archived",
    "candidate",
    "closed",
    "current",
    "draft",
    "entwurf",
    "freigegeben",
    "implemented",
    "in review",
    "in prufung",
    "open",
    "published",
    "proposed",
    "rejected",
    "retired",
    "superseded",
    "veroffentlicht",
    "archiviert",
    "ersetzt",
}
ALLOWED_CONFORMANCE_VALUES = {
    "accepted",
    "compliant",
    "conformant",
    "implemented",
    "yes",
}
INACTIVE_LIFECYCLE_VALUES = {
    "archived",
    "archiviert",
    "candidate",
    "proposed",
    "rejected",
    "retired",
    "superseded",
    "ersetzt",
}
BASELINE_TRUE_VALUES = {
    "accepted",
    "active",
    "current",
    "mandatory",
    "required",
    "true",
    "yes",
}
PLACEHOLDER_PATTERNS = (
    re.compile(r"\b(?:FIXME|PLACEHOLDER|TBD|TODO)\b", re.IGNORECASE),
    re.compile(r"\{\{[^{}\n]+\}\}"),
    re.compile(r"\$\{[^{}\n]+\}"),
    re.compile(r"<<[^<>\n]+>>"),
    re.compile(
        r"\[(?:insert|enter|replace|select|choose|name|owner|date|value|text)[^\]\n]*\]",
        re.IGNORECASE,
    ),
)
HTML_COMMENT = re.compile(r"<!--[\s\S]*?-->")
DECISION_TOKEN = re.compile(r"PGE-DEC-", re.IGNORECASE)
DECISION_TITLE_ID = re.compile(
    r"(?<![A-Z0-9])PGE-DEC-(\d{3})(?![A-Z0-9])",
    re.IGNORECASE,
)
DECISION_ID_VALUE = re.compile(r"^PGE-DEC-(\d{3})$", re.IGNORECASE)
VERSION_VALUE = re.compile(r"^v?\d+(?:\.\d+){0,2}$", re.IGNORECASE)
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
H2_TITLE = re.compile(r"^(\d{2})\s+\S(?:.*\S)?$")
H3_TITLE = re.compile(r"^(\d{2})\.(\d{2})\s+\S(?:.*\S)?$")
ENGAGEMENT_NUMBER = re.compile(r"^\d{2}$")
ENGAGEMENT_CODE = re.compile(r"^[A-Z0-9]{3}$")


class ConformanceError(RuntimeError):
    """Raised for input, API, or snapshot contract failures."""


def https_origin(value: str, *, require_origin_only: bool) -> tuple[str, int]:
    """Return a normalized HTTPS origin or reject an unsafe URL."""

    if not value or value != value.strip():
        raise ConformanceError("Confluence URLs must not be blank or contain surrounding whitespace")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConformanceError("Confluence URL contains an invalid port") from exc
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (require_origin_only and parsed.path not in {"", "/"})
        or (require_origin_only and (parsed.params or parsed.query or parsed.fragment))
    ):
        raise ConformanceError(
            "PGE_CONFLUENCE_BASE_URL must be an exact HTTPS origin without "
            "credentials, path, query, or fragment"
        )
    return parsed.hostname.casefold().rstrip("."), port or 443


class SameOriginRedirectHandler(HTTPRedirectHandler):
    """Allow redirects only when the Basic credential stays on its HTTPS origin."""

    def __init__(self, allowed_origin: tuple[str, int]) -> None:
        super().__init__()
        self.allowed_origin = allowed_origin

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        try:
            redirect_origin = https_origin(new_url, require_origin_only=False)
        except ConformanceError as exc:
            raise ConformanceError(
                "Confluence redirect attempted to leave the configured HTTPS origin"
            ) from exc
        if redirect_origin != self.allowed_origin:
            raise ConformanceError(
                "Confluence redirect attempted to leave the configured HTTPS origin"
            )
        return super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            new_url,
        )


@dataclass(frozen=True)
class Page:
    page_id: str
    title: str
    parent_id: str | None
    body_storage: str
    status: str
    version: int | None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.page_id,
            "title": self.title,
            "parent_id": self.parent_id,
            "type": "page",
            "status": self.status,
            "version": self.version,
            "body_storage": self.body_storage,
        }


@dataclass(frozen=True)
class IgnoredContent:
    content_id: str
    content_type: str
    title: str
    parent_id: str
    depth: int | None = None
    classification: str = "direct"
    classified_subtree_root_id: str | None = None
    delegated_target_name: str | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.content_id,
            "type": self.content_type,
            "title": self.title,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "classification": self.classification,
            "classified_subtree_root_id": self.classified_subtree_root_id,
            "delegated_target_name": self.delegated_target_name,
        }


@dataclass(frozen=True)
class ExclusionAuthority:
    page_id: str
    version: int

    def snapshot(self) -> dict[str, Any]:
        return {"page_id": self.page_id, "version": self.version}


@dataclass(frozen=True)
class DelegatedSubtree:
    root_page_id: str
    target_name: str

    def snapshot(self) -> dict[str, str]:
        return {
            "root_page_id": self.root_page_id,
            "target_name": self.target_name,
        }


@dataclass(frozen=True)
class ClassificationCounts:
    direct_validated: int
    delegated: int
    disposition_excluded: int

    @property
    def total(self) -> int:
        return self.direct_validated + self.delegated + self.disposition_excluded

    def snapshot(self) -> dict[str, int]:
        return {
            "direct_validated": self.direct_validated,
            "delegated": self.delegated,
            "disposition_excluded": self.disposition_excluded,
        }


@dataclass(frozen=True)
class NonPageClassificationCounts:
    direct: int
    delegated: int
    disposition_excluded: int

    @property
    def total(self) -> int:
        return self.direct + self.delegated + self.disposition_excluded

    def snapshot(self) -> dict[str, int]:
        return {
            "direct": self.direct,
            "delegated": self.delegated,
            "disposition_excluded": self.disposition_excluded,
        }


@dataclass(frozen=True)
class ExcludedPage:
    page_id: str
    title: str
    parent_id: str
    status: str
    depth: int
    excluded_subtree_root_id: str

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.page_id,
            "title": self.title,
            "parent_id": self.parent_id,
            "type": "page",
            "status": self.status,
            "depth": self.depth,
            "excluded_subtree_root_id": self.excluded_subtree_root_id,
        }


@dataclass(frozen=True)
class DelegatedPage:
    page_id: str
    title: str
    parent_id: str
    status: str
    depth: int
    delegated_subtree_root_id: str
    delegated_target_name: str

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.page_id,
            "title": self.title,
            "parent_id": self.parent_id,
            "type": "page",
            "status": self.status,
            "depth": self.depth,
            "delegated_subtree_root_id": self.delegated_subtree_root_id,
            "delegated_target_name": self.delegated_target_name,
        }


@dataclass(frozen=True)
class Target:
    name: str
    root_page_id: str
    profile: str
    traversal: str = "recursive"
    expected_page_count: int | None = None
    expected_non_page_count: int | None = None
    expected_content_count: int | None = None
    expected_decision_set: str | None = None
    namespace: str | None = None
    scope: str | None = None
    excluded_subtree_root_ids: tuple[str, ...] = ()
    exclusion_authorities: tuple[ExclusionAuthority, ...] = ()
    delegated_subtrees: tuple[DelegatedSubtree, ...] = ()
    expected_classification_counts: ClassificationCounts | None = None
    expected_non_page_classification_counts: NonPageClassificationCounts | None = None

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", self.name):
            raise ConformanceError(f"invalid target name: {self.name!r}")
        if not self.root_page_id.isdigit():
            raise ConformanceError(f"{self.name}: root_page_id must contain digits only")
        if self.profile not in ALLOWED_PROFILES:
            raise ConformanceError(f"{self.name}: unsupported profile {self.profile!r}")
        if self.traversal not in ALLOWED_TRAVERSAL_MODES:
            raise ConformanceError(
                f"{self.name}: unsupported traversal mode {self.traversal!r}"
            )
        if self.expected_page_count is not None and (
            not isinstance(self.expected_page_count, int)
            or isinstance(self.expected_page_count, bool)
            or self.expected_page_count < 1
        ):
            raise ConformanceError(f"{self.name}: expected_page_count must be positive")
        if self.expected_non_page_count is not None and (
            not isinstance(self.expected_non_page_count, int)
            or isinstance(self.expected_non_page_count, bool)
            or self.expected_non_page_count < 0
        ):
            raise ConformanceError(
                f"{self.name}: expected_non_page_count must be non-negative"
            )
        if self.expected_content_count is not None and (
            not isinstance(self.expected_content_count, int)
            or isinstance(self.expected_content_count, bool)
            or self.expected_content_count < 1
        ):
            raise ConformanceError(
                f"{self.name}: expected_content_count must be positive"
            )
        if (
            self.expected_page_count is not None
            and self.expected_non_page_count is not None
            and self.expected_content_count is not None
            and self.expected_page_count + self.expected_non_page_count
            != self.expected_content_count
        ):
            raise ConformanceError(
                f"{self.name}: expected page and non-page counts must sum to content count"
            )
        if len(self.excluded_subtree_root_ids) != len(set(self.excluded_subtree_root_ids)):
            raise ConformanceError(
                f"{self.name}: excluded_subtree_root_ids must be unique"
            )
        if any(not page_id.isdigit() for page_id in self.excluded_subtree_root_ids):
            raise ConformanceError(
                f"{self.name}: excluded_subtree_root_ids must contain digits only"
            )
        if self.root_page_id in self.excluded_subtree_root_ids:
            raise ConformanceError(f"{self.name}: the target root cannot be excluded")
        authority_ids = [authority.page_id for authority in self.exclusion_authorities]
        if len(authority_ids) != len(set(authority_ids)) or any(
            not page_id.isdigit() for page_id in authority_ids
        ):
            raise ConformanceError(
                f"{self.name}: exclusion authority page IDs must be unique digits"
            )
        if any(
            not isinstance(authority.version, int)
            or isinstance(authority.version, bool)
            or authority.version < 1
            for authority in self.exclusion_authorities
        ):
            raise ConformanceError(
                f"{self.name}: exclusion authority versions must be positive"
            )
        if bool(self.excluded_subtree_root_ids) != bool(self.exclusion_authorities):
            raise ConformanceError(
                f"{self.name}: subtree exclusions require versioned authorities"
            )
        if self.excluded_subtree_root_ids and self.traversal != "recursive":
            raise ConformanceError(
                f"{self.name}: subtree exclusions require recursive traversal"
            )
        delegated_roots = [delegation.root_page_id for delegation in self.delegated_subtrees]
        if len(delegated_roots) != len(set(delegated_roots)) or any(
            not root_id.isdigit() for root_id in delegated_roots
        ):
            raise ConformanceError(
                f"{self.name}: delegated subtree root IDs must be unique digits"
            )
        if self.root_page_id in delegated_roots:
            raise ConformanceError(f"{self.name}: the target root cannot be delegated")
        if set(delegated_roots).intersection(self.excluded_subtree_root_ids):
            raise ConformanceError(
                f"{self.name}: a subtree root cannot be both excluded and delegated"
            )
        if any(
            not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", delegation.target_name)
            or delegation.target_name == self.name
            for delegation in self.delegated_subtrees
        ):
            raise ConformanceError(f"{self.name}: invalid delegated target name")
        if self.delegated_subtrees and self.traversal != "recursive":
            raise ConformanceError(
                f"{self.name}: delegated subtrees require recursive traversal"
            )
        if self.expected_classification_counts is not None:
            counts = self.expected_classification_counts
            if any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in (
                    counts.direct_validated,
                    counts.delegated,
                    counts.disposition_excluded,
                )
            ):
                raise ConformanceError(
                    f"{self.name}: expected classification counts must be non-negative integers"
                )
            if self.expected_page_count is None or counts.total != self.expected_page_count:
                raise ConformanceError(
                    f"{self.name}: expected classification counts must sum to expected_page_count"
                )
        if self.expected_non_page_classification_counts is not None:
            counts = self.expected_non_page_classification_counts
            if any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in (
                    counts.direct,
                    counts.delegated,
                    counts.disposition_excluded,
                )
            ):
                raise ConformanceError(
                    f"{self.name}: expected non-page classification counts must be non-negative integers"
                )
            if (
                self.expected_non_page_count is None
                or counts.total != self.expected_non_page_count
            ):
                raise ConformanceError(
                    f"{self.name}: expected non-page classifications must sum to expected_non_page_count"
                )
        if self.profile == "engagement":
            if not self.namespace or not self.scope:
                raise ConformanceError(
                    f"{self.name}: engagement profile requires namespace and scope"
                )
            for label, value in (("namespace", self.namespace), ("scope", self.scope)):
                if not re.fullmatch(r"[A-Z0-9]{2,8}", value):
                    raise ConformanceError(f"{self.name}: invalid {label} {value!r}")

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "root_page_id": self.root_page_id,
            "profile": self.profile,
            "traversal": self.traversal,
            "expected_page_count": self.expected_page_count,
            "expected_non_page_count": self.expected_non_page_count,
            "expected_content_count": self.expected_content_count,
            "expected_decision_set": self.expected_decision_set,
            "namespace": self.namespace,
            "scope": self.scope,
            "excluded_subtree_root_ids": list(self.excluded_subtree_root_ids),
            "exclusion_authorities": [
                authority.snapshot() for authority in self.exclusion_authorities
            ],
            "delegated_subtree_targets": [
                delegation.snapshot() for delegation in self.delegated_subtrees
            ],
            "expected_classification_counts": (
                self.expected_classification_counts.snapshot()
                if self.expected_classification_counts is not None
                else None
            ),
            "expected_non_page_classification_counts": (
                self.expected_non_page_classification_counts.snapshot()
                if self.expected_non_page_classification_counts is not None
                else None
            ),
        }


@dataclass
class Tree:
    target: Target
    pages: list[Page]
    ignored_content: list[IgnoredContent] = field(default_factory=list)
    excluded_pages: list[ExcludedPage] = field(default_factory=list)
    delegated_pages: list[DelegatedPage] = field(default_factory=list)

    @property
    def page_count(self) -> int:
        return len(self.pages) + len(self.excluded_pages) + len(self.delegated_pages)

    @property
    def non_page_count(self) -> int:
        return len(self.ignored_content)

    @property
    def content_count(self) -> int:
        return self.page_count + self.non_page_count

    def non_page_classification_counts(self) -> NonPageClassificationCounts:
        return NonPageClassificationCounts(
            direct=sum(
                1 for item in self.ignored_content if item.classification == "direct"
            ),
            delegated=sum(
                1
                for item in self.ignored_content
                if item.classification == "delegated"
            ),
            disposition_excluded=sum(
                1
                for item in self.ignored_content
                if item.classification == "excluded"
            ),
        )

    def excluded_subtree_counts(self) -> dict[str, int]:
        counts = {root_id: 0 for root_id in self.target.excluded_subtree_root_ids}
        for page in self.excluded_pages:
            counts[page.excluded_subtree_root_id] = (
                counts.get(page.excluded_subtree_root_id, 0) + 1
            )
        return counts

    def delegated_subtree_counts(self) -> dict[tuple[str, str], int]:
        counts = {
            (delegation.root_page_id, delegation.target_name): 0
            for delegation in self.target.delegated_subtrees
        }
        for page in self.delegated_pages:
            key = (page.delegated_subtree_root_id, page.delegated_target_name)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def excluded_non_page_subtree_counts(self) -> dict[str, int]:
        counts = {root_id: 0 for root_id in self.target.excluded_subtree_root_ids}
        for item in self.ignored_content:
            if (
                item.classification == "excluded"
                and item.classified_subtree_root_id is not None
            ):
                root_id = item.classified_subtree_root_id
                counts[root_id] = counts.get(root_id, 0) + 1
        return counts

    def delegated_non_page_subtree_counts(self) -> dict[tuple[str, str], int]:
        counts = {
            (delegation.root_page_id, delegation.target_name): 0
            for delegation in self.target.delegated_subtrees
        }
        for item in self.ignored_content:
            if (
                item.classification == "delegated"
                and item.classified_subtree_root_id is not None
                and item.delegated_target_name is not None
            ):
                key = (
                    item.classified_subtree_root_id,
                    item.delegated_target_name,
                )
                counts[key] = counts.get(key, 0) + 1
        return counts

    def snapshot(self) -> dict[str, Any]:
        return {
            **self.target.snapshot(),
            "pages": [page.snapshot() for page in self.pages],
            "excluded_pages": [page.snapshot() for page in self.excluded_pages],
            "delegated_pages": [page.snapshot() for page in self.delegated_pages],
            "ignored_content": [item.snapshot() for item in self.ignored_content],
        }


@dataclass(frozen=True)
class Alignment:
    name: str
    template_target: str
    catalog_target: str
    product_source_artifacts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    target: str
    message: str
    page_id: str | None = None
    page_title: str | None = None


@dataclass(frozen=True)
class Heading:
    level: int
    title: str
    position: int


@dataclass(frozen=True)
class Cell:
    text: str
    explicitly_bold: bool
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class Table:
    rows: list[list[Cell]]
    position: int


@dataclass
class Macro:
    name: str
    start: int
    end: int | None = None


@dataclass(frozen=True)
class Block:
    kind: str
    position: int


@dataclass
class _CellBuilder:
    segments: list[tuple[str, bool]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def build(self) -> Cell:
        material = [(text, bold) for text, bold in self.segments if text.strip()]
        return Cell(
            text=normalize_space("".join(text for text, _ in self.segments)),
            explicitly_bold=bool(material) and all(bold for _, bold in material),
            references=tuple(dict.fromkeys(self.references)),
        )


@dataclass
class _TableBuilder:
    position: int
    rows: list[list[Cell]] = field(default_factory=list)
    current_row: list[Cell] | None = None
    current_cell: _CellBuilder | None = None


class StorageParser(HTMLParser):
    """Extract the structural elements required by the documentation rules."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.position = 0
        self.bold_depth = 0
        self.heading_stack: list[tuple[int, int, list[str]]] = []
        self.headings: list[Heading] = []
        self.table_stack: list[_TableBuilder] = []
        self.tables: list[Table] = []
        self.macro_stack: list[Macro] = []
        self.macros: list[Macro] = []
        self.blocks: list[Block] = []
        self.text_parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.position += 1
        tag = tag.casefold()
        attributes = {key.casefold(): value or "" for key, value in attrs}
        if tag in {"b", "strong"}:
            self.bold_depth += 1
        if tag in {"h1", "h2", "h3"}:
            level = int(tag[1])
            self.heading_stack.append((level, self.position, []))
            self.blocks.append(Block(kind=tag, position=self.position))
        if tag == "table":
            builder = _TableBuilder(position=self.position)
            self.table_stack.append(builder)
            self.blocks.append(Block(kind="table", position=self.position))
        elif tag == "tr" and self.table_stack:
            self.table_stack[-1].current_row = []
        elif tag in {"th", "td"} and self.table_stack:
            self.table_stack[-1].current_cell = _CellBuilder()
        elif tag == "a" and self.table_stack and self.table_stack[-1].current_cell:
            href = attributes.get("href", "")
            if href:
                self.table_stack[-1].current_cell.references.append(href)
        elif tag == "ri:page" and self.table_stack and self.table_stack[-1].current_cell:
            reference = attributes.get(
                "ri:content-title",
                attributes.get("content-title", ""),
            )
            if reference:
                self.table_stack[-1].current_cell.references.append(reference)
        if tag == "ac:structured-macro":
            macro = Macro(
                name=attributes.get("ac:name", attributes.get("name", "")).casefold(),
                start=self.position,
            )
            self.macro_stack.append(macro)
            self.macros.append(macro)
            self.blocks.append(Block(kind=f"macro:{macro.name or 'unknown'}", position=self.position))
        elif tag == "hr":
            self.blocks.append(Block(kind="hr", position=self.position))
        elif tag in {"p", "ul", "ol", "pre", "blockquote"}:
            self.blocks.append(Block(kind=tag, position=self.position))

    def handle_endtag(self, tag: str) -> None:
        self.position += 1
        tag = tag.casefold()
        if tag in {"h1", "h2", "h3"} and self.heading_stack:
            level, start, parts = self.heading_stack.pop()
            self.headings.append(
                Heading(level=level, title=normalize_space("".join(parts)), position=start)
            )
        if tag in {"th", "td"} and self.table_stack:
            table = self.table_stack[-1]
            if table.current_cell is not None and table.current_row is not None:
                table.current_row.append(table.current_cell.build())
            table.current_cell = None
        elif tag == "tr" and self.table_stack:
            table = self.table_stack[-1]
            if table.current_row is not None:
                table.rows.append(table.current_row)
            table.current_row = None
        elif tag == "table" and self.table_stack:
            table = self.table_stack.pop()
            self.tables.append(Table(rows=table.rows, position=table.position))
        if tag == "ac:structured-macro" and self.macro_stack:
            macro = self.macro_stack.pop()
            macro.end = self.position
        if tag in {"b", "strong"}:
            self.bold_depth = max(0, self.bold_depth - 1)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        self.position += 1
        self.text_parts.append(data)
        if self.heading_stack:
            self.heading_stack[-1][2].append(data)
        if self.table_stack and self.table_stack[-1].current_cell is not None:
            self.table_stack[-1].current_cell.segments.append(
                (data, self.bold_depth > 0)
            )

    @property
    def plain_text(self) -> str:
        return normalize_space(" ".join(self.text_parts))


def normalize_space(value: str) -> str:
    return " ".join(value.replace("\xa0", " ").split())


def normalized_key(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    ascii_value = "".join(char for char in decomposed if not unicodedata.combining(char))
    return re.sub(r"[^a-z0-9]+", " ", ascii_value.casefold()).strip()


FIELD_ALIASES = {
    "document id": "document_id",
    "dokument id": "document_id",
    "document id version": "document_id_version",
    "dokument id version": "document_id_version",
    "template id": "document_id",
    "template set id version": "template_id_version",
    "template id version": "template_id_version",
    "template status": "template_status",
    "artifact id": "document_id",
    "artefakt id": "document_id",
    "register id": "document_id",
    "catalog id version": "document_id_version",
    "standard id version": "document_id_version",
    "decision id": "decision_id",
    "entscheidungs id": "decision_id",
    "decision status": "decision_status",
    "entscheidungsstatus": "decision_status",
    "decision date": "decision_date",
    "entscheidungsdatum": "decision_date",
    "decision owner": "decision_owner",
    "entscheidungsverantwortlicher": "decision_owner",
    "approver": "approver",
    "freigeber": "approver",
    "reviewer note": "reviewer_note",
    "review hinweis": "reviewer_note",
    "status": "status",
    "version": "version",
    "owner": "owner",
    "document owner": "owner",
    "dokument owner": "owner",
    "dokumentverantwortlicher": "owner",
    "reviewer": "reviewer",
    "prufer": "reviewer",
    "classification": "classification",
    "klassifizierung": "classification",
    "scope": "scope",
    "anwendungsbereich": "scope",
    "geltungsbereich": "scope",
    "target scope": "scope",
    "documentation standard": "documentation_standard",
    "dokumentationsstandard": "documentation_standard",
    "documentation conformance": "documentation_conformance",
    "dokumentationskonformitat": "documentation_conformance",
    "engagement id": "engagement_id",
    "customer assessment entity": "customer_entity",
    "kunde assessment entity": "customer_entity",
    "engagement scope": "engagement_scope",
    "scope target": "scope_target",
    "engagement owner": "engagement_owner",
    "engagement reviewer": "engagement_reviewer",
    "documentation architecture": "documentation_architecture",
    "dokumentationsarchitektur": "documentation_architecture",
    "pge delivery mode": "delivery_mode",
    "pge liefermodus": "delivery_mode",
    "leading documentation entry": "leading_entry",
    "fuhrender dokumentationseinstieg": "leading_entry",
    "leading source": "leading_source",
    "fuhrende quelle": "leading_source",
    "fuhrendes system": "leading_source",
    "source of truth": "leading_source",
    "artifact type": "artifact_type",
    "artefakttyp": "artifact_type",
    "pge artefakt": "artifact_type",
    "artifact": "artifact_type",
    "kanonische template oder produktquelle": "artifact_source",
    "canonical template or product source": "artifact_source",
    "template or product source": "artifact_source",
    "page type": "page_type",
    "seitentyp": "page_type",
    "document type": "page_type",
    "dokumenttyp": "page_type",
}


def canonical_field(value: str) -> str:
    key = normalized_key(value)
    return FIELD_ALIASES.get(key, key.replace(" ", "_"))


def parse_storage(body_storage: str) -> StorageParser:
    parser = StorageParser()
    try:
        parser.feed(body_storage)
        parser.close()
    except (AssertionError, ValueError) as exc:
        raise ConformanceError(f"cannot parse Confluence storage content: {exc}") from exc
    return parser


def table_header(table: Table) -> list[str]:
    if not table.rows:
        return []
    return [canonical_field(cell.text) for cell in table.rows[0]]


def table_records(table: Table) -> list[dict[str, str]]:
    header = table_header(table)
    if not header:
        return []
    records: list[dict[str, str]] = []
    for row in table.rows[1:]:
        record = {
            header[index]: cell.text
            for index, cell in enumerate(row)
            if index < len(header) and header[index]
        }
        if any(value.strip() for value in record.values()):
            records.append(record)
    return records


def extract_metadata(parser: StorageParser) -> tuple[dict[str, str], Table | None]:
    for table in sorted(parser.tables, key=lambda current: current.position):
        header = table_header(table)
        if len(header) >= 2 and header[0] in {"field", "feld"} and header[1] in {
            "value",
            "wert",
        }:
            result: dict[str, str] = {}
            for row in table.rows[1:]:
                if len(row) < 2 or not row[0].text:
                    continue
                result[canonical_field(row[0].text)] = row[1].text
            return result, table
    return {}, None


def contains_placeholder(value: str) -> bool:
    return any(pattern.search(value) for pattern in PLACEHOLDER_PATTERNS)


def template_page(page: Page, metadata: dict[str, str]) -> bool:
    title = normalized_key(page.title)
    if "template" in title.split() or "vorlage" in title.split():
        return True
    if metadata.get("template_id_version") or metadata.get("template_status"):
        return True
    page_type = normalized_key(metadata.get("page_type", ""))
    return "template" in page_type.split() or "vorlage" in page_type.split()


def add_finding(
    findings: list[Finding],
    severity: str,
    code: str,
    target: Target,
    message: str,
    page: Page | None = None,
) -> None:
    findings.append(
        Finding(
            severity=severity,
            code=code,
            target=target.name,
            message=message,
            page_id=page.page_id if page else None,
            page_title=page.title if page else None,
        )
    )


def engagement_root_descriptor(page: Page, target: Target) -> str | None:
    if target.profile != "engagement" or target.namespace is None or target.scope is None:
        return None
    prefix = f"{target.namespace}-"
    forbidden_prefix = f"{target.namespace}-{target.scope}-"
    if not page.title.startswith(prefix) or page.title.startswith(forbidden_prefix):
        return None
    descriptor = page.title[len(prefix) :]
    if not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", descriptor):
        return None
    return descriptor


def readable_title_key(value: str) -> str:
    words = normalized_key(value).split()
    return " ".join(word for word in words if word not in {"and", "und"})


def technical_product_descriptor(page: Page, target: Target) -> str | None:
    if target.profile != "product":
        return None
    match = re.fullmatch(
        r"LIT-PGE-(?:[A-Z0-9]+-)*\d{2,3}-(?P<descriptor>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)",
        page.title,
    )
    return match.group("descriptor") if match else None


def expected_readable_heading(page: Page, target: Target) -> str | None:
    if target.profile == "product":
        return technical_product_descriptor(page, target) or page.title
    if target.profile != "engagement":
        return page.title
    if page.page_id == target.root_page_id:
        return engagement_root_descriptor(page, target)
    assert target.namespace is not None
    assert target.scope is not None
    parsed = parse_engagement_name(page.title, target.namespace, target.scope)
    return parsed.descriptor if parsed else None


def validate_headings(
    page: Page,
    parser: StorageParser,
    target: Target,
    findings: list[Finding],
) -> None:
    h1 = [heading for heading in parser.headings if heading.level == 1]
    if len(h1) != 1:
        add_finding(
            findings,
            "error",
            "heading.h1-count",
            target,
            "The page must contain exactly one H1 heading.",
            page,
        )
    else:
        expected_heading = expected_readable_heading(page, target)
        technical_product_title = technical_product_descriptor(page, target)
        if target.profile == "engagement" or technical_product_title is not None:
            heading_matches = expected_heading is not None and (
                readable_title_key(h1[0].title)
                == readable_title_key(expected_heading.replace("-", " "))
            )
        else:
            heading_matches = normalize_space(h1[0].title) == normalize_space(page.title)
        if not heading_matches:
            add_finding(
                findings,
                "error",
                "heading.h1-title",
                target,
                (
                    "The H1 must be the readable content title without namespace, "
                    "scope, inherited codes, or ordering number."
                    if target.profile == "engagement"
                    or technical_product_title is not None
                    else "The H1 heading must exactly equal the Confluence page title."
                ),
                page,
            )

    h2 = [heading for heading in parser.headings if heading.level == 2]
    if not h2 or h2[0].title != "00 Inhaltsverzeichnis":
        add_finding(
            findings,
            "error",
            "heading.toc-title",
            target,
            "The first H2 must be exactly '00 Inhaltsverzeichnis'.",
            page,
        )

    for index, heading in enumerate(h2):
        match = H2_TITLE.fullmatch(heading.title)
        expected = f"{index:02d}"
        if not match:
            add_finding(
                findings,
                "error",
                "heading.h2-format",
                target,
                "Every H2 must start with a two-digit chapter number and a title.",
                page,
            )
        elif match.group(1) != expected:
            add_finding(
                findings,
                "error",
                "heading.h2-sequence",
                target,
                f"H2 chapter numbers must be contiguous; expected {expected}.",
                page,
            )

    current_major: int | None = None
    expected_minor = 1
    for heading in sorted(
        (item for item in parser.headings if item.level in {2, 3}),
        key=lambda item: item.position,
    ):
        if heading.level == 2:
            match = H2_TITLE.fullmatch(heading.title)
            current_major = int(match.group(1)) if match else None
            expected_minor = 1
            continue
        match = H3_TITLE.fullmatch(heading.title)
        if not match:
            add_finding(
                findings,
                "error",
                "heading.h3-format",
                target,
                "Every H3 must start with its two-level numeric chapter identifier.",
                page,
            )
            continue
        major, minor = int(match.group(1)), int(match.group(2))
        if current_major is None or major != current_major:
            add_finding(
                findings,
                "error",
                "heading.h3-parent",
                target,
                "The H3 major number must match its containing H2 chapter.",
                page,
            )
        if minor != expected_minor:
            add_finding(
                findings,
                "error",
                "heading.h3-sequence",
                target,
                f"H3 chapter numbers must be contiguous; expected {expected_minor:02d}.",
                page,
            )
            expected_minor = minor + 1
        else:
            expected_minor += 1

    if h2:
        first = h2[0]
        next_h2_position = h2[1].position if len(h2) > 1 else sys.maxsize
        associated_expand = False
        for macro in parser.macros:
            if macro.name != "expand" or macro.end is None:
                continue
            contains_heading = macro.start < first.position < macro.end
            follows_heading = first.position < macro.start < next_h2_position
            contains_toc = any(
                nested.name == "toc"
                and nested.end is not None
                and macro.start < nested.start < nested.end < macro.end
                for nested in parser.macros
            )
            if (contains_heading or follows_heading) and contains_toc:
                associated_expand = True
                break
        if not associated_expand:
            add_finding(
                findings,
                "error",
                "heading.toc-expand",
                target,
                "The 00 chapter must own or be immediately followed by an expand macro containing the TOC macro.",
                page,
            )

    numbered_headings = sorted(
        (heading for heading in parser.headings if heading.level == 2),
        key=lambda item: item.position,
    )
    for index, heading in enumerate(numbered_headings):
        end = sys.maxsize
        for candidate in numbered_headings[index + 1 :]:
            end = candidate.position
            break
        blocks = [
            block
            for block in parser.blocks
            if heading.position < block.position < end
            and block.kind not in {"h2", "h3"}
        ]
        if not blocks or blocks[-1].kind != "hr":
            add_finding(
                findings,
                "error",
                "heading.chapter-close",
                target,
                "Every H2 chapter must end with a horizontal rule before the next chapter or page end.",
                page,
            )


def validate_tables(
    page: Page,
    parser: StorageParser,
    target: Target,
    findings: list[Finding],
) -> None:
    for table_index, table in enumerate(
        sorted(parser.tables, key=lambda current: current.position),
        start=1,
    ):
        if not table.rows or not table.rows[0]:
            add_finding(
                findings,
                "error",
                "table.empty",
                target,
                f"Table {table_index} has no usable header row.",
                page,
            )
            continue
        for cell_index, cell in enumerate(table.rows[0], start=1):
            if not cell.text or not cell.explicitly_bold:
                add_finding(
                    findings,
                    "error",
                    "table.header-bold",
                    target,
                    f"Table {table_index}, header cell {cell_index} must contain explicitly bold text.",
                    page,
                )
        header = table_header(table)
        if len(header) >= 2 and header[0] in {"field", "feld"} and header[1] in {
            "value",
            "wert",
        }:
            for row_index, row in enumerate(table.rows[1:], start=2):
                if not row or not row[0].text or not row[0].explicitly_bold:
                    add_finding(
                        findings,
                        "error",
                        "table.field-bold",
                        target,
                        f"Table {table_index}, field cell in row {row_index} must contain explicitly bold text.",
                        page,
                    )


def validate_metadata(
    page: Page,
    parser: StorageParser,
    target: Target,
    findings: list[Finding],
) -> dict[str, str]:
    metadata, metadata_table = extract_metadata(parser)
    for combined_key in ("document_id_version", "template_id_version"):
        combined = metadata.get(combined_key, "")
        if not combined or "/" not in combined:
            continue
        identifier, version = (part.strip() for part in combined.rsplit("/", 1))
        if identifier:
            metadata.setdefault("document_id", identifier)
        if version:
            metadata.setdefault("version", version)
    if target.profile == "engagement":
        for destination, source_keys in {
            "scope": ("engagement_scope",),
            "owner": ("engagement_owner",),
            "reviewer": ("engagement_reviewer",),
            "leading_source": (
                "leading_entry",
                "documentation_architecture",
            ),
        }.items():
            for source_key in source_keys:
                if metadata.get(source_key):
                    metadata.setdefault(destination, metadata[source_key])
                    break
    is_decision = "decision_id" in metadata
    is_template = target.profile == "template" and template_page(page, metadata)
    if metadata_table is None:
        add_finding(
            findings,
            "error",
            "metadata.missing-table",
            target,
            "A Field/Value or Feld/Wert metadata table is required.",
            page,
        )
        return metadata
    seen_fields: set[str] = set()
    for row in metadata_table.rows[1:]:
        if not row or not row[0].text:
            continue
        field_name = canonical_field(row[0].text)
        if field_name in seen_fields:
            add_finding(
                findings,
                "error",
                "metadata.duplicate-field",
                target,
                f"Metadata field {field_name!r} occurs more than once.",
                page,
            )
        seen_fields.add(field_name)

    if is_decision:
        required = {
            "decision_id",
            "decision_status",
            "version",
            "decision_date",
            "decision_owner",
            "approver",
            "reviewer_note",
            "classification",
            "scope",
            "documentation_standard",
            "documentation_conformance",
        }
    elif target.profile == "engagement":
        required = {
            "document_id",
            "engagement_id",
            "customer_entity",
            "scope",
            "scope_target",
            "owner",
            "reviewer",
            "status",
            "classification",
            "version",
            "leading_source",
        }
    else:
        required = {
            "document_id",
            "status",
            "version",
            "owner",
            "reviewer",
            "classification",
            "scope",
            "leading_source",
            "documentation_standard",
            "documentation_conformance",
        }

    for key in sorted(required):
        value = normalize_space(metadata.get(key, ""))
        if not value:
            add_finding(
                findings,
                "error",
                "metadata.required",
                target,
                f"Mandatory metadata field {key!r} is missing or blank.",
                page,
            )
        elif contains_placeholder(value) and not is_template:
            add_finding(
                findings,
                "error",
                "metadata.placeholder",
                target,
                f"Mandatory metadata field {key!r} contains a placeholder.",
                page,
            )

    status_key = "decision_status" if is_decision else "status"
    if is_template and metadata.get("template_status"):
        status_key = "template_status"
    if status_key in metadata:
        value = normalized_key(metadata[status_key])
        if not contains_placeholder(metadata[status_key]) and value not in ALLOWED_STATUSES:
            add_finding(
                findings,
                "error",
                "metadata.status",
                target,
                "Status must use one controlled lifecycle value.",
                page,
            )
    if "classification" in metadata:
        value = normalized_key(metadata["classification"])
        if not contains_placeholder(metadata["classification"]) and value not in ALLOWED_CLASSIFICATIONS:
            add_finding(
                findings,
                "error",
                "metadata.classification",
                target,
                "Classification must be Public, Internal, Confidential, or Restricted.",
                page,
            )
    if (
        "version" in metadata
        and not contains_placeholder(metadata["version"])
        and not VERSION_VALUE.fullmatch(metadata["version"].strip())
    ):
        add_finding(
            findings,
            "error",
            "metadata.version",
            target,
            "Version must use a numeric version value such as 1.0.",
            page,
        )
    if "decision_date" in metadata and not ISO_DATE.fullmatch(metadata["decision_date"].strip()):
        add_finding(
            findings,
            "error",
            "metadata.date",
            target,
            "Decision date must use ISO format YYYY-MM-DD.",
            page,
        )
    if "documentation_standard" in metadata:
        standard = normalized_key(metadata["documentation_standard"])
        if "pge dec 036" not in standard and "documentation naming and page structure standard" not in standard:
            add_finding(
                findings,
                "error",
                "metadata.standard",
                target,
                "Documentation standard must reference PGE-DEC-036 or its canonical standard page.",
                page,
            )
    if "documentation_conformance" in metadata:
        value = normalized_key(metadata["documentation_conformance"])
        if value not in ALLOWED_CONFORMANCE_VALUES:
            add_finding(
                findings,
                "error",
                "metadata.conformance",
                target,
                "Documentation conformance must use an allowed affirmative value.",
                page,
            )
    return metadata


def validate_markers_and_placeholders(
    page: Page,
    parser: StorageParser,
    metadata: dict[str, str],
    target: Target,
    findings: list[Finding],
) -> None:
    if HTML_COMMENT.search(page.body_storage):
        add_finding(
            findings,
            "error",
            "content.hidden-marker",
            target,
            "HTML comments and hidden migration markers are forbidden.",
            page,
        )
    if contains_placeholder(parser.plain_text) and not (
        target.profile == "template" and template_page(page, metadata)
    ):
        add_finding(
            findings,
            "error",
            "content.placeholder",
            target,
            "Visible placeholders are permitted only on declared template pages.",
            page,
        )


def parse_decision_set(specification: str) -> set[str]:
    result: set[str] = set()
    for token in specification.split(","):
        token = token.strip()
        if not token:
            raise ConformanceError("decision set contains an empty item")
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if not re.fullmatch(r"\d{3}", start_text) or not re.fullmatch(
                r"\d{3}", end_text
            ):
                raise ConformanceError(f"invalid decision range: {token!r}")
            start, end = int(start_text), int(end_text)
            if start < 1 or end < start:
                raise ConformanceError(f"invalid decision range: {token!r}")
            result.update(f"{number:03d}" for number in range(start, end + 1))
        elif re.fullmatch(r"\d{3}", token) and int(token) > 0:
            result.add(token)
        else:
            raise ConformanceError(f"invalid decision identifier: {token!r}")
    return result


def validate_decisions(
    tree: Tree,
    metadata_by_page: dict[str, dict[str, str]],
    findings: list[Finding],
) -> None:
    if tree.target.profile != "product" or not tree.target.expected_decision_set:
        return
    expected = parse_decision_set(tree.target.expected_decision_set)
    found: dict[str, Page] = {}
    for page in tree.pages:
        metadata = metadata_by_page.get(page.page_id, {})
        raw_metadata_id = metadata.get("decision_id")
        title_ids = DECISION_TITLE_ID.findall(page.title)
        if DECISION_TOKEN.search(page.title) and not title_ids:
            add_finding(
                findings,
                "error",
                "decision.invalid-title-id",
                tree.target,
                "A title contains a malformed PGE decision identifier.",
                page,
            )
        if raw_metadata_id is None:
            if title_ids:
                add_finding(
                    findings,
                    "error",
                    "decision.metadata-id",
                    tree.target,
                    "A title identifier requires matching Decision-ID metadata.",
                    page,
                )
            continue
        metadata_match = DECISION_ID_VALUE.fullmatch(raw_metadata_id.strip())
        if metadata_match is None:
            add_finding(
                findings,
                "error",
                "decision.invalid-id",
                tree.target,
                "Decision-ID metadata must use the exact form PGE-DEC-NNN.",
                page,
            )
            continue
        decision_id = metadata_match.group(1)
        if decision_id in found:
            add_finding(
                findings,
                "error",
                "decision.duplicate",
                tree.target,
                f"Decision identifier {decision_id} occurs more than once.",
                page,
            )
        else:
            found[decision_id] = page
        if len(title_ids) > 1:
            add_finding(
                findings,
                "error",
                "decision.ambiguous-title-id",
                tree.target,
                "A title must not contain more than one PGE decision identifier.",
                page,
            )
        if title_ids and any(title_id != decision_id for title_id in title_ids):
            add_finding(
                findings,
                "error",
                "decision.title-metadata-conflict",
                tree.target,
                "The optional title identifier conflicts with Decision-ID metadata.",
                page,
            )
        if normalized_key(metadata.get("decision_status", "")) != "accepted":
            add_finding(
                findings,
                "error",
                "decision.accepted-status",
                tree.target,
                "Every decision in the accepted decision set must have status Accepted.",
                page,
            )
    for decision_id in sorted(expected - set(found)):
        add_finding(
            findings,
            "error",
            "decision.missing",
            tree.target,
            f"Expected decision PGE-DEC-{decision_id} is missing.",
        )
    for decision_id in sorted(set(found) - expected):
        add_finding(
            findings,
            "error",
            "decision.unexpected",
            tree.target,
            f"Unexpected decision PGE-DEC-{decision_id} is present.",
            found[decision_id],
        )


@dataclass(frozen=True)
class EngagementName:
    namespace: str
    scope: str
    codes: tuple[str, ...]
    number: str
    descriptor: str


def parse_engagement_name(title: str, namespace: str, scope: str) -> EngagementName | None:
    prefix = f"{namespace}-{scope}-"
    if not title.startswith(prefix):
        return None
    parts = title[len(prefix) :].split("-")
    number_index = next(
        (index for index, part in enumerate(parts) if ENGAGEMENT_NUMBER.fullmatch(part)),
        None,
    )
    if number_index is None or number_index == len(parts) - 1:
        return None
    codes = tuple(parts[:number_index])
    if any(not ENGAGEMENT_CODE.fullmatch(code) for code in codes):
        return None
    descriptor = "-".join(parts[number_index + 1 :])
    if not descriptor or not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", descriptor):
        return None
    return EngagementName(
        namespace=namespace,
        scope=scope,
        codes=codes,
        number=parts[number_index],
        descriptor=descriptor,
    )


def derive_area_code(descriptor: str) -> str:
    words = [re.sub(r"[^A-Za-z0-9]", "", word) for word in descriptor.split("-")]
    words = [
        word
        for word in words
        if word and word.casefold() not in {"and", "of", "the"}
    ]
    if not words:
        raise ConformanceError("cannot derive an area code from an empty descriptor")
    if len(words) >= 3:
        return "".join(word[0] for word in words[:3]).upper()
    if len(words) == 2:
        if len(words[1]) < 2:
            raise ConformanceError(f"cannot derive three letters from {descriptor!r}")
        return (words[0][0] + words[1][:2]).upper()
    if len(words[0]) < 3:
        raise ConformanceError(f"cannot derive three letters from {descriptor!r}")
    return words[0][:3].upper()


def validate_engagement_names(tree: Tree, findings: list[Finding]) -> None:
    target = tree.target
    if target.profile != "engagement":
        return
    assert target.namespace is not None
    assert target.scope is not None
    page_by_id = {page.page_id: page for page in tree.pages}
    parsed: dict[str, EngagementName] = {}
    root = page_by_id.get(target.root_page_id)
    if root is None:
        add_finding(
            findings,
            "error",
            "naming.root-missing",
            target,
            "The configured engagement root page is not present in the selected tree.",
        )
    else:
        descriptor = engagement_root_descriptor(root, target)
        if descriptor is None:
            add_finding(
                findings,
                "error",
                "naming.root",
                target,
                (
                    "The engagement root must use <Namespace>-<Content-Name> "
                    "without scope code, ordering number, or inherited area code."
                ),
                root,
            )
        else:
            parsed[root.page_id] = EngagementName(
                namespace=target.namespace,
                scope=target.scope,
                codes=(),
                number="",
                descriptor=descriptor,
            )
    for page in tree.pages:
        if page.page_id == target.root_page_id:
            continue
        current = parse_engagement_name(page.title, target.namespace, target.scope)
        if current is None:
            add_finding(
                findings,
                "error",
                "naming.format",
                target,
                "Page title does not match the engagement naming grammar.",
                page,
            )
            continue
        parsed[page.page_id] = current
    for page in tree.pages:
        if page.page_id == target.root_page_id or page.page_id not in parsed:
            continue
        parent = page_by_id.get(page.parent_id or "")
        if parent is None or parent.page_id not in parsed:
            add_finding(
                findings,
                "error",
                "naming.parent",
                target,
                "Parent page is unavailable for inherited-code verification.",
                page,
            )
            continue
        parent_name = parsed[parent.page_id]
        expected_codes = parent_name.codes
        if parent.page_id != target.root_page_id:
            expected_codes = (*expected_codes, derive_area_code(parent_name.descriptor))
        if parsed[page.page_id].codes != expected_codes:
            add_finding(
                findings,
                "error",
                "naming.inherited-code",
                target,
                "Inherited three-letter area codes do not match the parent hierarchy.",
                page,
            )


def validate_tree(tree: Tree) -> tuple[list[Finding], dict[str, StorageParser]]:
    findings: list[Finding] = []
    target = tree.target
    if target.expected_page_count is not None and tree.page_count != target.expected_page_count:
        add_finding(
            findings,
            "error",
            "tree.page-count",
            target,
            f"Expected {target.expected_page_count} pages but retrieved {tree.page_count}.",
        )
    if (
        target.expected_non_page_count is not None
        and tree.non_page_count != target.expected_non_page_count
    ):
        add_finding(
            findings,
            "error",
            "tree.non-page-count",
            target,
            (
                f"Expected {target.expected_non_page_count} non-page nodes but "
                f"retrieved {tree.non_page_count}."
            ),
        )
    if (
        target.expected_content_count is not None
        and tree.content_count != target.expected_content_count
    ):
        add_finding(
            findings,
            "error",
            "tree.content-count",
            target,
            (
                f"Expected {target.expected_content_count} content nodes but "
                f"retrieved {tree.content_count}."
            ),
        )
    if target.expected_classification_counts is not None:
        expected_counts = target.expected_classification_counts.snapshot()
        actual_counts = {
            "direct_validated": len(tree.pages),
            "delegated": len(tree.delegated_pages),
            "disposition_excluded": len(tree.excluded_pages),
        }
        for classification, expected_count in expected_counts.items():
            if actual_counts[classification] != expected_count:
                add_finding(
                    findings,
                    "error",
                    "tree.classification-count",
                    target,
                    (
                        f"Expected {expected_count} {classification} pages but "
                        f"retrieved {actual_counts[classification]}."
                    ),
                )
    if target.expected_non_page_classification_counts is not None:
        expected_counts = target.expected_non_page_classification_counts.snapshot()
        actual_counts = tree.non_page_classification_counts().snapshot()
        for classification, expected_count in expected_counts.items():
            if actual_counts[classification] != expected_count:
                add_finding(
                    findings,
                    "error",
                    "tree.non-page-classification-count",
                    target,
                    (
                        f"Expected {expected_count} {classification} non-page nodes "
                        f"but retrieved {actual_counts[classification]}."
                    ),
                )
    for ignored in tree.ignored_content:
        findings.append(
            Finding(
                severity="info",
                code="tree.non-page-inventoried",
                target=target.name,
                message=(
                    f"Inventoried non-page content of type {ignored.content_type!r} "
                    f"with classification {ignored.classification!r}."
                ),
                page_id=ignored.content_id,
                page_title=ignored.title,
            )
        )
    page_ids = [page.page_id for page in tree.pages]
    excluded_ids = [page.page_id for page in tree.excluded_pages]
    delegated_ids = [page.page_id for page in tree.delegated_pages]
    content_ids = [
        *page_ids,
        *excluded_ids,
        *delegated_ids,
        *(item.content_id for item in tree.ignored_content),
    ]
    if len(content_ids) != len(set(content_ids)):
        add_finding(
            findings,
            "error",
            "tree.duplicate-content",
            target,
            "The retrieved tree contains duplicate content identifiers.",
        )
    if target.root_page_id not in set(page_ids):
        add_finding(
            findings,
            "error",
            "tree.root-missing",
            target,
            "The configured root page is missing from the retrieved tree.",
        )
    page_by_id = {page.page_id: page for page in tree.pages}
    for authority in target.exclusion_authorities:
        authority_page = page_by_id.get(authority.page_id)
        if authority_page is None:
            add_finding(
                findings,
                "error",
                "tree.exclusion-authority-missing",
                target,
                f"Exclusion authority page {authority.page_id} is not included in the tree.",
            )
        elif authority_page.version != authority.version:
            add_finding(
                findings,
                "error",
                "tree.exclusion-authority-version",
                target,
                (
                    f"Exclusion authority page {authority.page_id} is version "
                    f"{authority_page.version!r}; reviewed version {authority.version} is required."
                ),
                authority_page,
            )
    has_excluded_non_page = any(
        item.classification == "excluded" for item in tree.ignored_content
    )
    has_delegated_non_page = any(
        item.classification == "delegated" for item in tree.ignored_content
    )
    if (tree.excluded_pages or has_excluded_non_page) and not target.excluded_subtree_root_ids:
        add_finding(
            findings,
            "error",
            "tree.unconfigured-exclusion",
            target,
            "The tree contains excluded content without configured subtree roots.",
        )
    if (tree.delegated_pages or has_delegated_non_page) and not target.delegated_subtrees:
        add_finding(
            findings,
            "error",
            "tree.unconfigured-delegation",
            target,
            "The tree contains delegated content without configured subtree targets.",
        )
    if target.excluded_subtree_root_ids or target.delegated_subtrees:
        parent_by_id = {
            **{
                page.page_id: page.parent_id
                for page in tree.pages
                if page.parent_id is not None
            },
            **{page.page_id: page.parent_id for page in tree.excluded_pages},
            **{page.page_id: page.parent_id for page in tree.delegated_pages},
            **{
                item.content_id: item.parent_id for item in tree.ignored_content
            },
        }
        counts = tree.excluded_subtree_counts()
        for root_id, count in counts.items():
            if count == 0 or root_id not in set(excluded_ids):
                add_finding(
                    findings,
                    "error",
                    "tree.excluded-root-missing",
                    target,
                    f"Configured excluded subtree root {root_id} is not present.",
                )
        delegated_counts = tree.delegated_subtree_counts()
        for (root_id, delegated_target), count in delegated_counts.items():
            if count == 0 or root_id not in set(delegated_ids):
                add_finding(
                    findings,
                    "error",
                    "tree.delegated-root-missing",
                    target,
                    (
                        f"Delegated subtree root {root_id} for target "
                        f"{delegated_target} is not present."
                    ),
                )
        for page in tree.pages:
            if page.page_id == target.root_page_id:
                continue
            try:
                classification = classified_subtree(
                    page.page_id,
                    parent_by_id,
                    target,
                )
            except ConformanceError as exc:
                add_finding(
                    findings,
                    "error",
                    "tree.classification",
                    target,
                    str(exc),
                    page,
                )
                continue
            if classification is not None:
                add_finding(
                    findings,
                    "error",
                    "tree.included-under-classified-subtree",
                    target,
                    "A directly validated page is located below a classified subtree root.",
                    page,
                )
        for page in tree.excluded_pages:
            try:
                classification = classified_subtree(
                    page.page_id,
                    parent_by_id,
                    target,
                )
            except ConformanceError as exc:
                add_finding(
                    findings,
                    "error",
                    "tree.classification",
                    target,
                    str(exc),
                )
                continue
            expected = ("excluded", page.excluded_subtree_root_id, None)
            if classification != expected:
                add_finding(
                    findings,
                    "error",
                    "tree.excluded-root-mismatch",
                    target,
                    "An excluded page is assigned to the wrong subtree root.",
                )
        for page in tree.delegated_pages:
            try:
                classification = classified_subtree(
                    page.page_id,
                    parent_by_id,
                    target,
                )
            except ConformanceError as exc:
                add_finding(
                    findings,
                    "error",
                    "tree.classification",
                    target,
                    str(exc),
                )
                continue
            expected = (
                "delegated",
                page.delegated_subtree_root_id,
                page.delegated_target_name,
            )
            if classification != expected:
                add_finding(
                    findings,
                    "error",
                    "tree.delegated-root-mismatch",
                    target,
                    "A delegated page is assigned to the wrong subtree target.",
                )
        for item in tree.ignored_content:
            try:
                classification = classified_subtree(
                    item.content_id,
                    parent_by_id,
                    target,
                )
            except ConformanceError as exc:
                findings.append(
                    Finding(
                        severity="error",
                        code="tree.classification",
                        target=target.name,
                        message=str(exc),
                        page_id=item.content_id,
                        page_title=item.title,
                    )
                )
                continue
            expected = (
                ("direct", None, None)
                if classification is None
                else classification
            )
            actual = (
                item.classification,
                item.classified_subtree_root_id,
                item.delegated_target_name,
            )
            if actual != expected:
                findings.append(
                    Finding(
                        severity="error",
                        code="tree.non-page-classification",
                        target=target.name,
                        message="A non-page node is assigned to the wrong scope.",
                        page_id=item.content_id,
                        page_title=item.title,
                    )
                )

    parsers: dict[str, StorageParser] = {}
    metadata_by_page: dict[str, dict[str, str]] = {}
    for page in tree.pages:
        try:
            parser = parse_storage(page.body_storage)
        except ConformanceError as exc:
            add_finding(
                findings,
                "error",
                "content.parse",
                target,
                str(exc),
                page,
            )
            continue
        parsers[page.page_id] = parser
        metadata = validate_metadata(page, parser, target, findings)
        metadata_by_page[page.page_id] = metadata
        validate_markers_and_placeholders(page, parser, metadata, target, findings)
        validate_headings(page, parser, target, findings)
        validate_tables(page, parser, target, findings)
    validate_decisions(tree, metadata_by_page, findings)
    validate_engagement_names(tree, findings)
    return findings, parsers


def validate_delegated_coverage(trees: Sequence[Tree]) -> list[Finding]:
    """Prove that every delegated inventory is validated by its named target."""

    findings: list[Finding] = []
    tree_by_name = {tree.target.name: tree for tree in trees}
    for source_tree in trees:
        for delegation in source_tree.target.delegated_subtrees:
            coverage_tree = tree_by_name.get(delegation.target_name)
            if coverage_tree is None:
                add_finding(
                    findings,
                    "error",
                    "tree.delegated-target-missing",
                    source_tree.target,
                    (
                        f"Delegated target {delegation.target_name} was not selected; "
                        f"subtree {delegation.root_page_id} has no validation coverage."
                    ),
                )
                continue
            if coverage_tree.target.root_page_id != delegation.root_page_id:
                add_finding(
                    findings,
                    "error",
                    "tree.delegated-target-root",
                    source_tree.target,
                    (
                        f"Delegated target {delegation.target_name} is rooted at "
                        f"{coverage_tree.target.root_page_id}, not {delegation.root_page_id}."
                    ),
                )
                continue
            delegated_ids = {
                page.page_id
                for page in source_tree.delegated_pages
                if page.delegated_subtree_root_id == delegation.root_page_id
                and page.delegated_target_name == delegation.target_name
            }
            covered_ids = {
                *(page.page_id for page in coverage_tree.pages),
                *(page.page_id for page in coverage_tree.excluded_pages),
                *(page.page_id for page in coverage_tree.delegated_pages),
            }
            delegated_non_page_ids = {
                item.content_id
                for item in source_tree.ignored_content
                if item.classification == "delegated"
                and item.classified_subtree_root_id == delegation.root_page_id
                and item.delegated_target_name == delegation.target_name
            }
            covered_non_page_ids = {
                item.content_id for item in coverage_tree.ignored_content
            }
            if (
                delegated_ids != covered_ids
                or delegated_non_page_ids != covered_non_page_ids
            ):
                add_finding(
                    findings,
                    "error",
                    "tree.delegated-coverage-mismatch",
                    source_tree.target,
                    (
                        f"Delegated subtree {delegation.root_page_id} inventories "
                        f"{len(delegated_ids)} pages and "
                        f"{len(delegated_non_page_ids)} non-page nodes, while target "
                        f"{delegation.target_name} covers {len(covered_ids)} pages and "
                        f"{len(covered_non_page_ids)} non-page nodes."
                    ),
                )
    return findings


@dataclass(frozen=True)
class ArtifactRecord:
    name: str
    status: str
    baseline: str
    page_id: str
    source_references: tuple[str, ...] = ()


def normalize_artifact_name(value: str) -> str:
    normalized = normalized_key(value)
    normalized = re.sub(r"\b(?:and|und)\b", " ", normalized)
    normalized = re.sub(r"\badr\b", " ", normalized)
    normalized = re.sub(r"^(?:pge\s+)?(?:\d+\s+)?", "", normalized)
    normalized = re.sub(r"\s+(?:template|vorlage)$", "", normalized)
    normalized = normalize_space(normalized)
    aliases = {
        "evidence record package": "evidence package",
        "lab demo nightly validation report": "lab demo nightly validation report",
    }
    return aliases.get(normalized, normalized)


def cell_records(table: Table) -> list[dict[str, Cell]]:
    header = table_header(table)
    if not header:
        return []
    return [
        {
            header[index]: cell
            for index, cell in enumerate(row)
            if index < len(header) and header[index]
        }
        for row in table.rows[1:]
        if any(cell.text.strip() for cell in row)
    ]


def artifact_records(tree: Tree, parsers: dict[str, StorageParser]) -> list[ArtifactRecord]:
    records: list[ArtifactRecord] = []
    for page in tree.pages:
        parser = parsers.get(page.page_id)
        if parser is None:
            continue
        metadata, _ = extract_metadata(parser)
        artifact_type = metadata.get("artifact_type", "")
        if artifact_type:
            records.append(
                ArtifactRecord(
                    name=normalize_artifact_name(artifact_type),
                    status=normalized_key(metadata.get("status", "active")),
                    baseline=normalized_key(metadata.get("baseline", "")),
                    page_id=page.page_id,
                )
            )
        template_status = normalized_key(
            metadata.get("template_status", metadata.get("status", "active"))
        )
        if tree.target.profile == "template":
            template_heading_found = False
            for heading in parser.headings:
                match = re.match(
                    r"^\d{2}(?:\.\d{2})?\s+Vorlage:\s*(.+)$",
                    heading.title,
                    re.IGNORECASE,
                )
                if not match:
                    continue
                template_heading_found = True
                names = [match.group(1)]
                if normalize_artifact_name(match.group(1)) == "evidence register evidence package":
                    names = ["Evidence Register", "Evidence Package"]
                records.extend(
                    ArtifactRecord(
                        name=normalize_artifact_name(name),
                        status=template_status,
                        baseline="",
                        page_id=page.page_id,
                    )
                    for name in names
                )
            if (
                page.page_id != tree.target.root_page_id
                and not template_heading_found
            ):
                records.append(
                    ArtifactRecord(
                        name=normalize_artifact_name(page.title),
                        status=normalized_key(metadata.get("status", "active")),
                        baseline="",
                        page_id=page.page_id,
                    )
                )
        for table in parser.tables:
            header = table_header(table)
            if "artifact_type" not in header:
                continue
            for record in cell_records(table):
                artifact_cell = record.get("artifact_type")
                if artifact_cell is None:
                    continue
                name = normalize_artifact_name(artifact_cell.text)
                if not name:
                    continue
                source_cell = record.get("artifact_source")
                records.append(
                    ArtifactRecord(
                        name=name,
                        status=normalized_key(
                            (
                                record.get("status")
                                or record.get("lifecycle")
                                or Cell("active", False)
                            ).text
                        ),
                        baseline=normalized_key(
                            (
                                record.get("baseline")
                                or record.get("required")
                                or record.get("mandatory")
                                or Cell("", False)
                            ).text
                        ),
                        page_id=page.page_id,
                        source_references=(
                            tuple(source_cell.references)
                            if source_cell is not None
                            else ()
                        ),
                    )
                )
    return records


def active_record(record: ArtifactRecord) -> bool:
    return record.status not in INACTIVE_LIFECYCLE_VALUES


def validate_alignment(
    alignment: Alignment,
    trees: dict[str, Tree],
    parsers: dict[str, dict[str, StorageParser]],
) -> list[Finding]:
    findings: list[Finding] = []
    template_tree = trees.get(alignment.template_target)
    catalog_tree = trees.get(alignment.catalog_target)
    if template_tree is None or catalog_tree is None:
        return findings
    templates = artifact_records(template_tree, parsers[template_tree.target.name])
    catalog = artifact_records(catalog_tree, parsers[catalog_tree.target.name])
    if not templates:
        add_finding(
            findings,
            "error",
            "alignment.template-empty",
            template_tree.target,
            "No artifact types could be extracted from the Template Library.",
        )
    if not catalog:
        add_finding(
            findings,
            "error",
            "alignment.catalog-empty",
            catalog_tree.target,
            "No artifact types could be extracted from the Artifact Catalog.",
        )
    for record in (*templates, *catalog):
        if record.status in {"candidate", "proposed"} and record.baseline in BASELINE_TRUE_VALUES:
            owner = (
                template_tree.target
                if record in templates
                else catalog_tree.target
            )
            page = next((item for item in trees[owner.name].pages if item.page_id == record.page_id), None)
            add_finding(
                findings,
                "error",
                "alignment.proposed-baseline",
                owner,
                "A Proposed or Candidate artifact must not be represented as baseline.",
                page,
            )
    active_templates = {record.name for record in templates if active_record(record)}
    active_catalog = {record.name for record in catalog if active_record(record)}
    allowed_product_sources = {
        normalize_artifact_name(name) for name in alignment.product_source_artifacts
    }
    for name in sorted(active_catalog - active_templates - allowed_product_sources):
        add_finding(
            findings,
            "error",
            "alignment.template-missing",
            template_tree.target,
            f"Current catalog artifact {name!r} has no current template mapping.",
        )
    template_title_ids = {
        normalized_key(page.title): page.page_id for page in template_tree.pages
    }
    for record in catalog:
        if not active_record(record):
            continue
        if not record.source_references:
            page = next(
                (item for item in catalog_tree.pages if item.page_id == record.page_id),
                None,
            )
            add_finding(
                findings,
                "error",
                "alignment.source-missing",
                catalog_tree.target,
                "Every current catalog artifact must link its canonical template or product source.",
                page,
            )
            continue
        if record.name in allowed_product_sources:
            continue
        referenced_ids: set[str] = set()
        for reference in record.source_references:
            page_match = re.search(r"/pages/(\d+)(?:/|$|[?#])", reference)
            if page_match:
                referenced_ids.add(page_match.group(1))
            title_id = template_title_ids.get(normalized_key(reference))
            if title_id:
                referenced_ids.add(title_id)
        matching_template_ids = {
            template.page_id
            for template in templates
            if active_record(template) and template.name == record.name
        }
        if matching_template_ids and not referenced_ids.intersection(matching_template_ids):
            page = next(
                (item for item in catalog_tree.pages if item.page_id == record.page_id),
                None,
            )
            add_finding(
                findings,
                "error",
                "alignment.source-mismatch",
                catalog_tree.target,
                "The current catalog artifact does not link the template page that defines it.",
                page,
            )
    for name in sorted(active_templates - active_catalog):
        add_finding(
            findings,
            "error",
            "alignment.catalog-missing",
            catalog_tree.target,
            f"Current template artifact {name!r} has no current catalog entry.",
        )
    return findings


class ConfluenceClient:
    """Minimal, read-only Confluence Cloud REST API v2 client."""

    def __init__(
        self,
        base_url: str,
        email: str,
        token: str,
        *,
        allowed_origin: str = DEFAULT_ALLOWED_CONFLUENCE_ORIGIN,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.api_origin = https_origin(base_url, require_origin_only=True)
        reviewed_origin = https_origin(allowed_origin, require_origin_only=True)
        if self.api_origin != reviewed_origin:
            raise ConformanceError(
                "PGE_CONFLUENCE_BASE_URL does not match the reviewed allowed origin"
            )
        normalized = base_url.rstrip("/")
        self.api_base = f"{normalized}/wiki/api/v2"
        if not email or not token:
            raise ConformanceError("Confluence read-only identity and token are required")
        self.authorization = "Basic " + base64.b64encode(
            f"{email}:{token}".encode("utf-8")
        ).decode("ascii")
        self.timeout = timeout
        self.opener = build_opener(SameOriginRedirectHandler(self.api_origin))

    def _get_json(self, path: str, parameters: dict[str, str | int]) -> dict[str, Any]:
        query = urlencode(parameters)
        url = f"{self.api_base}/{path.lstrip('/')}"
        if query:
            url += f"?{query}"
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": self.authorization,
                "User-Agent": "modulix-validation-pge-conformance/1",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                payload = json.load(response)
                link_header = response.headers.get("Link", "")
        except HTTPError as exc:
            raise ConformanceError(
                f"Confluence returned HTTP {exc.code} for {path.split('?')[0]}"
            ) from None
        except URLError as exc:
            raise ConformanceError(f"Confluence request failed for {path.split('?')[0]}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConformanceError("Confluence returned an invalid JSON response") from exc
        if not isinstance(payload, dict):
            raise ConformanceError("Confluence response root must be an object")
        header_next = self._next_link_from_header(link_header)
        links = payload.get("_links")
        if header_next and (
            not isinstance(links, dict) or not links.get("next")
        ):
            if not isinstance(links, dict):
                links = {}
                payload["_links"] = links
            links["next"] = header_next
        return payload

    @staticmethod
    def _next_link_from_header(value: str) -> str | None:
        for part in value.split(","):
            match = re.match(r'\s*<([^>]+)>\s*;(.*)$', part)
            if not match:
                continue
            parameters = {
                item.strip().casefold()
                for item in match.group(2).split(";")
            }
            if 'rel="next"' in parameters or "rel=next" in parameters:
                return match.group(1)
        return None

    def page(self, page_id: str) -> Page:
        payload = self._get_json(f"pages/{page_id}", {"body-format": "storage"})
        if str(payload.get("id", "")) != page_id or payload.get("type", "page") != "page":
            raise ConformanceError(f"Confluence returned the wrong page for ID {page_id}")
        body_container = payload.get("body")
        body = (
            body_container.get("storage")
            if isinstance(body_container, dict)
            else None
        )
        if not isinstance(body, dict) or not isinstance(body.get("value"), str):
            raise ConformanceError(f"Page {page_id} has no storage-format body")
        title = payload.get("title")
        if not isinstance(title, str) or not title.strip():
            raise ConformanceError(f"Page {page_id} has no title")
        version_container = payload.get("version")
        version_value = (
            version_container.get("number")
            if isinstance(version_container, dict)
            else None
        )
        parent_value = payload.get("parentId")
        if parent_value is not None and not str(parent_value).isdigit():
            raise ConformanceError(f"Page {page_id} has an invalid parent ID")
        return Page(
            page_id=page_id,
            title=title,
            parent_id=str(parent_value) if parent_value is not None else None,
            body_storage=body["value"],
            status=str(payload.get("status", "current")),
            version=(
                version_value
                if isinstance(version_value, int) and not isinstance(version_value, bool)
                else None
            ),
        )

    @staticmethod
    def _next_cursor(payload: dict[str, Any]) -> str | None:
        links = payload.get("_links", {})
        next_link = links.get("next") if isinstance(links, dict) else None
        if next_link:
            parsed = urlparse(str(next_link))
            cursors = parse_qs(parsed.query).get("cursor", [])
            if len(cursors) != 1 or not cursors[0]:
                raise ConformanceError("Confluence pagination link has no unambiguous cursor")
            return cursors[0]
        meta = payload.get("meta", {})
        if isinstance(meta, dict) and meta.get("hasMore") is True:
            raise ConformanceError("Confluence reports more children without a next cursor")
        return None

    def direct_children(
        self,
        page_id: str,
    ) -> tuple[list[dict[str, Any]], list[IgnoredContent]]:
        children: list[dict[str, Any]] = []
        ignored: list[IgnoredContent] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            parameters: dict[str, str | int] = {"limit": 250}
            if cursor is not None:
                parameters["cursor"] = cursor
            payload = self._get_json(f"pages/{page_id}/direct-children", parameters)
            results = payload.get("results")
            if not isinstance(results, list):
                raise ConformanceError(f"Children response for {page_id} has no results list")
            for item in results:
                if not isinstance(item, dict):
                    raise ConformanceError(f"Children response for {page_id} contains a non-object")
                content_id = str(item.get("id", ""))
                content_type = str(item.get("type", "unknown"))
                title = str(item.get("title", ""))
                if not content_id.isdigit():
                    raise ConformanceError(
                        f"Children response for {page_id} contains an invalid ID"
                    )
                if content_type == "page":
                    children.append(item)
                else:
                    ignored.append(
                        IgnoredContent(
                            content_id=content_id,
                            content_type=content_type,
                            title=title,
                            parent_id=page_id,
                        )
                    )
            cursor = self._next_cursor(payload)
            if cursor is None:
                break
            if cursor in seen_cursors:
                raise ConformanceError(f"Pagination cursor repeated for parent {page_id}")
            seen_cursors.add(cursor)
        return children, ignored

    def descendants(
        self,
        page_id: str,
        max_pages: int,
    ) -> tuple[list[dict[str, Any]], list[IgnoredContent]]:
        """Inventory all descendants, including pages below non-page containers."""

        pages: list[dict[str, Any]] = []
        ignored: list[IgnoredContent] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_content_ids: set[str] = set()
        while True:
            parameters: dict[str, str | int] = {"depth": 10, "limit": 250}
            if cursor is not None:
                parameters["cursor"] = cursor
            payload = self._get_json(f"pages/{page_id}/descendants", parameters)
            results = payload.get("results")
            if not isinstance(results, list):
                raise ConformanceError(
                    f"Descendants response for {page_id} has no results list"
                )
            for item in results:
                if not isinstance(item, dict):
                    raise ConformanceError(
                        f"Descendants response for {page_id} contains a non-object"
                    )
                content_id = str(item.get("id", ""))
                content_type = str(item.get("type", "unknown"))
                parent_id = str(item.get("parentId", ""))
                title = str(item.get("title", ""))
                depth = item.get("depth")
                if (
                    not content_id.isdigit()
                    or not parent_id.isdigit()
                    or not isinstance(depth, int)
                    or isinstance(depth, bool)
                    or depth < 1
                    or depth > 10
                ):
                    raise ConformanceError(
                        f"Descendants response for {page_id} contains invalid identity or depth"
                    )
                if content_id in seen_content_ids or content_id == page_id:
                    raise ConformanceError(
                        f"Content {content_id} occurs more than once in the recursive inventory"
                    )
                if depth == 10:
                    raise ConformanceError(
                        f"Target rooted at {page_id} reaches the API depth limit; "
                        "complete traversal cannot be proven"
                    )
                seen_content_ids.add(content_id)
                if content_type == "page":
                    pages.append(item)
                    if len(pages) + 1 > max_pages:
                        raise ConformanceError(
                            f"Target rooted at {page_id} exceeds the maximum of {max_pages} pages"
                        )
                else:
                    ignored.append(
                        IgnoredContent(
                            content_id=content_id,
                            content_type=content_type,
                            title=title,
                            parent_id=parent_id,
                            depth=depth,
                        )
                    )
            cursor = self._next_cursor(payload)
            if cursor is None:
                break
            if cursor in seen_cursors:
                raise ConformanceError(
                    f"Pagination cursor repeated for descendants of {page_id}"
                )
            seen_cursors.add(cursor)
        return pages, ignored


def classified_subtree(
    content_id: str,
    parent_by_id: dict[str, str],
    target: Target,
) -> tuple[str, str, str | None] | None:
    excluded = set(target.excluded_subtree_root_ids)
    delegated = {
        delegation.root_page_id: delegation.target_name
        for delegation in target.delegated_subtrees
    }
    current = content_id
    visited: set[str] = set()
    while current != target.root_page_id:
        if current in visited:
            raise ConformanceError(
                f"Target {target.name} contains a parent cycle at {current}"
        )
        visited.add(current)
        if current in delegated:
            return "delegated", current, delegated[current]
        if current in excluded:
            # Item-level dispositions may intentionally nest.  The closest
            # configured ancestor is the most specific authority for this
            # content and keeps per-root counts disjoint.
            return "excluded", current, None
        parent = parent_by_id.get(current)
        if parent is None:
            raise ConformanceError(
                f"Target {target.name} cannot trace content {content_id} to its root"
        )
        current = parent
    return None


def classify_non_page_content(
    item: IgnoredContent,
    parent_by_id: dict[str, str],
    target: Target,
) -> IgnoredContent:
    classification = classified_subtree(item.content_id, parent_by_id, target)
    if classification is None:
        return IgnoredContent(
            content_id=item.content_id,
            content_type=item.content_type,
            title=item.title,
            parent_id=item.parent_id,
            depth=item.depth,
        )
    classification_type, subtree_root, delegated_target = classification
    return IgnoredContent(
        content_id=item.content_id,
        content_type=item.content_type,
        title=item.title,
        parent_id=item.parent_id,
        depth=item.depth,
        classification=classification_type,
        classified_subtree_root_id=subtree_root,
        delegated_target_name=delegated_target,
    )


def crawl_classified_tree(
    client: ConfluenceClient,
    target: Target,
    max_pages: int,
) -> Tree:
    root = client.page(target.root_page_id)
    page_summaries, ignored = client.descendants(target.root_page_id, max_pages)
    all_summaries: list[dict[str, Any]] = [*page_summaries]
    all_summaries.extend(
        {
            "id": item.content_id,
            "parentId": item.parent_id,
            "type": item.content_type,
        }
        for item in ignored
    )
    parent_by_id = {
        str(item["id"]): str(item["parentId"]) for item in all_summaries
    }
    page_ids = {str(item["id"]) for item in page_summaries}
    configured_roots = {
        *target.excluded_subtree_root_ids,
        *(delegation.root_page_id for delegation in target.delegated_subtrees),
    }
    missing_roots = sorted(configured_roots - page_ids)
    if missing_roots:
        raise ConformanceError(
            f"Target {target.name} is missing classified subtree roots: "
            f"{', '.join(missing_roots)}"
        )

    pages = [root]
    excluded_pages: list[ExcludedPage] = []
    delegated_pages: list[DelegatedPage] = []
    for summary in page_summaries:
        page_id = str(summary["id"])
        classification = classified_subtree(page_id, parent_by_id, target)
        if classification is None:
            page = client.page(page_id)
            expected_parent = str(summary["parentId"])
            if page.parent_id != expected_parent:
                raise ConformanceError(
                    f"Page {page_id} reports parent {page.parent_id!r}; "
                    f"expected {expected_parent!r}"
                )
            pages.append(page)
            continue
        classification_type, subtree_root, delegated_target = classification
        if classification_type == "excluded":
            excluded_pages.append(
                ExcludedPage(
                    page_id=page_id,
                    title=str(summary.get("title", "")),
                    parent_id=str(summary["parentId"]),
                    status=str(summary.get("status", "current")),
                    depth=int(summary["depth"]),
                    excluded_subtree_root_id=subtree_root,
                )
            )
            continue
        if delegated_target is None:
            raise ConformanceError(
                f"Target {target.name} has an invalid delegated classification"
            )
        delegated_pages.append(
            DelegatedPage(
                page_id=page_id,
                title=str(summary.get("title", "")),
                parent_id=str(summary["parentId"]),
                status=str(summary.get("status", "current")),
                depth=int(summary["depth"]),
                delegated_subtree_root_id=subtree_root,
                delegated_target_name=delegated_target,
            )
        )
    classified_non_page = [
        classify_non_page_content(item, parent_by_id, target) for item in ignored
    ]
    return Tree(
        target=target,
        pages=pages,
        ignored_content=classified_non_page,
        excluded_pages=excluded_pages,
        delegated_pages=delegated_pages,
    )


def crawl_tree(client: ConfluenceClient, target: Target, max_pages: int) -> Tree:
    if target.excluded_subtree_root_ids or target.delegated_subtrees:
        return crawl_classified_tree(client, target, max_pages)
    root = client.page(target.root_page_id)
    pages = [root]
    ignored_content: list[IgnoredContent] = []
    if target.traversal == "page-only":
        _, ignored_content = client.direct_children(root.page_id)
        return Tree(target=target, pages=pages, ignored_content=ignored_content)
    queue = [root]
    seen = {root.page_id}
    while queue:
        parent = queue.pop(0)
        children, ignored = client.direct_children(parent.page_id)
        ignored_content.extend(ignored)
        for child_summary in children:
            child_id = str(child_summary["id"])
            if child_id in seen:
                raise ConformanceError(f"Page {child_id} occurs more than once in the recursive tree")
            child = client.page(child_id)
            if child.parent_id != parent.page_id:
                raise ConformanceError(
                    f"Page {child_id} reports parent {child.parent_id!r}; expected {parent.page_id!r}"
                )
            seen.add(child_id)
            pages.append(child)
            queue.append(child)
            if len(pages) > max_pages:
                raise ConformanceError(
                    f"Target {target.name} exceeds the maximum of {max_pages} pages"
                )
    return Tree(target=target, pages=pages, ignored_content=ignored_content)


def target_from_mapping(data: dict[str, Any]) -> Target:
    raw_excluded_roots = data.get("excluded_subtree_root_ids", [])
    if not isinstance(raw_excluded_roots, list) or any(
        not isinstance(value, str) for value in raw_excluded_roots
    ):
        raise ConformanceError(
            "excluded_subtree_root_ids must be a list of page-ID strings"
        )
    raw_authorities = data.get("exclusion_authorities", [])
    if not isinstance(raw_authorities, list) or any(
        not isinstance(value, dict) for value in raw_authorities
    ):
        raise ConformanceError("exclusion_authorities must be a list of objects")
    authorities: list[ExclusionAuthority] = []
    for value in raw_authorities:
        if set(value) != {"page_id", "version"}:
            raise ConformanceError(
                "each exclusion authority requires only page_id and version"
            )
        version = value["version"]
        if (
            not isinstance(value["page_id"], str)
            or not isinstance(version, int)
            or isinstance(version, bool)
        ):
            raise ConformanceError(
                "exclusion authority page_id must be a string and version an integer"
            )
        authorities.append(
            ExclusionAuthority(page_id=str(value["page_id"]), version=version)
        )
    raw_counts: dict[str, int | None] = {}
    for count_name in (
        "expected_page_count",
        "expected_non_page_count",
        "expected_content_count",
    ):
        value = data.get(count_name)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool)
        ):
            raise ConformanceError(f"{count_name} must be an integer or null")
        raw_counts[count_name] = value
    raw_classification_counts = data.get("expected_classification_counts")
    classification_counts: ClassificationCounts | None = None
    if raw_classification_counts is not None:
        required_count_keys = {
            "direct_validated",
            "delegated",
            "disposition_excluded",
        }
        if (
            not isinstance(raw_classification_counts, dict)
            or set(raw_classification_counts) != required_count_keys
            or any(
                not isinstance(raw_classification_counts[key], int)
                or isinstance(raw_classification_counts[key], bool)
                for key in required_count_keys
            )
        ):
            raise ConformanceError(
                "expected_classification_counts must contain three integer counts"
            )
        classification_counts = ClassificationCounts(
            direct_validated=raw_classification_counts["direct_validated"],
            delegated=raw_classification_counts["delegated"],
            disposition_excluded=raw_classification_counts["disposition_excluded"],
        )
    raw_non_page_classification_counts = data.get(
        "expected_non_page_classification_counts"
    )
    non_page_classification_counts: NonPageClassificationCounts | None = None
    if raw_non_page_classification_counts is not None:
        required_non_page_keys = {
            "direct",
            "delegated",
            "disposition_excluded",
        }
        if (
            not isinstance(raw_non_page_classification_counts, dict)
            or set(raw_non_page_classification_counts) != required_non_page_keys
            or any(
                not isinstance(raw_non_page_classification_counts[key], int)
                or isinstance(raw_non_page_classification_counts[key], bool)
                for key in required_non_page_keys
            )
        ):
            raise ConformanceError(
                "expected_non_page_classification_counts must contain three integer counts"
            )
        non_page_classification_counts = NonPageClassificationCounts(
            direct=raw_non_page_classification_counts["direct"],
            delegated=raw_non_page_classification_counts["delegated"],
            disposition_excluded=raw_non_page_classification_counts[
                "disposition_excluded"
            ],
        )
    raw_delegations = data.get("delegated_subtree_targets", [])
    if not isinstance(raw_delegations, list) or any(
        not isinstance(value, dict) for value in raw_delegations
    ):
        raise ConformanceError("delegated_subtree_targets must be a list of objects")
    delegations: list[DelegatedSubtree] = []
    for value in raw_delegations:
        if set(value) != {"root_page_id", "target_name"}:
            raise ConformanceError(
                "each delegated subtree requires only root_page_id and target_name"
            )
        if not isinstance(value["root_page_id"], str) or not isinstance(
            value["target_name"], str
        ):
            raise ConformanceError(
                "delegated subtree root_page_id and target_name must be strings"
            )
        delegations.append(
            DelegatedSubtree(
                root_page_id=value["root_page_id"],
                target_name=value["target_name"],
            )
        )
    for field_name in ("name", "root_page_id", "profile"):
        if not isinstance(data.get(field_name), str):
            raise ConformanceError(f"target {field_name} must be a string")
    if "traversal" in data and not isinstance(data["traversal"], str):
        raise ConformanceError("target traversal must be a string")
    for field_name in ("expected_decision_set", "namespace", "scope"):
        if data.get(field_name) is not None and not isinstance(data[field_name], str):
            raise ConformanceError(f"target {field_name} must be a string or null")
    target = Target(
        name=data["name"],
        root_page_id=data["root_page_id"],
        profile=data["profile"],
        traversal=data.get("traversal", "recursive"),
        expected_page_count=raw_counts["expected_page_count"],
        expected_non_page_count=raw_counts["expected_non_page_count"],
        expected_content_count=raw_counts["expected_content_count"],
        expected_decision_set=(
            data["expected_decision_set"]
            if data.get("expected_decision_set") is not None
            else None
        ),
        namespace=data["namespace"] if data.get("namespace") is not None else None,
        scope=data["scope"] if data.get("scope") is not None else None,
        excluded_subtree_root_ids=tuple(raw_excluded_roots),
        exclusion_authorities=tuple(authorities),
        delegated_subtrees=tuple(delegations),
        expected_classification_counts=classification_counts,
        expected_non_page_classification_counts=non_page_classification_counts,
    )
    target.validate()
    if target.expected_decision_set:
        parse_decision_set(target.expected_decision_set)
    return target


def alignment_from_mapping(data: dict[str, Any], target_names: set[str]) -> Alignment:
    raw_sources = data.get("product_source_artifacts", [])
    if not isinstance(raw_sources, list) or any(
        not isinstance(value, str) or not value.strip() for value in raw_sources
    ):
        raise ConformanceError(
            "alignment product_source_artifacts must be a list of nonblank strings"
        )
    sources = tuple(value.strip() for value in raw_sources)
    if len(sources) != len(set(sources)):
        raise ConformanceError("alignment product_source_artifacts must be unique")
    for field_name in ("name", "template_target", "catalog_target"):
        if not isinstance(data.get(field_name), str):
            raise ConformanceError(f"alignment {field_name} must be a string")
    alignment = Alignment(
        name=data["name"],
        template_target=data["template_target"],
        catalog_target=data["catalog_target"],
        product_source_artifacts=sources,
    )
    if (
        not alignment.name
        or alignment.template_target not in target_names
        or alignment.catalog_target not in target_names
        or alignment.template_target == alignment.catalog_target
    ):
        raise ConformanceError(f"invalid alignment configuration: {alignment}")
    return alignment


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConformanceError(f"cannot read {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConformanceError(f"{path} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ConformanceError(f"{path} must contain a JSON object")
    return payload


def read_config(path: Path) -> tuple[str, list[Target], list[Alignment]]:
    payload = read_json(path)
    if payload.get("schema_version") != 1:
        raise ConformanceError("target config schema_version must be 1")
    allowed_origin = payload.get("allowed_confluence_origin")
    if not isinstance(allowed_origin, str):
        raise ConformanceError("target config requires allowed_confluence_origin")
    configured_origin = https_origin(allowed_origin, require_origin_only=True)
    reviewed_origin = https_origin(
        DEFAULT_ALLOWED_CONFLUENCE_ORIGIN,
        require_origin_only=True,
    )
    if configured_origin != reviewed_origin:
        raise ConformanceError(
            "target config allowed_confluence_origin differs from the reviewed origin"
        )
    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ConformanceError("target config requires a non-empty targets list")
    targets = [target_from_mapping(item) for item in raw_targets if isinstance(item, dict)]
    if len(targets) != len(raw_targets):
        raise ConformanceError("every configured target must be an object")
    names = [target.name for target in targets]
    if len(names) != len(set(names)):
        raise ConformanceError("target names must be unique")
    targets_by_name = {target.name: target for target in targets}
    for target in targets:
        for delegation in target.delegated_subtrees:
            delegated_target = targets_by_name.get(delegation.target_name)
            if delegated_target is None:
                raise ConformanceError(
                    f"{target.name}: delegated target {delegation.target_name!r} is missing"
                )
            if delegated_target.root_page_id != delegation.root_page_id:
                raise ConformanceError(
                    f"{target.name}: delegated root {delegation.root_page_id} does not "
                    f"match target {delegation.target_name}"
                )
    raw_alignments = payload.get("alignments", [])
    if not isinstance(raw_alignments, list):
        raise ConformanceError("target config alignments must be a list")
    alignments: list[Alignment] = []
    for item in raw_alignments:
        if not isinstance(item, dict):
            raise ConformanceError("every alignment must be an object")
        alignments.append(alignment_from_mapping(item, set(names)))
    return allowed_origin, targets, alignments


def page_from_snapshot(data: dict[str, Any]) -> Page:
    required = {"id", "title", "parent_id", "type", "status", "version", "body_storage"}
    if set(data) != required or data.get("type") != "page":
        raise ConformanceError("snapshot page uses an invalid schema")
    page_id = data["id"]
    if (
        not isinstance(page_id, str)
        or not page_id.isdigit()
        or not isinstance(data["title"], str)
        or not isinstance(data["status"], str)
        or not isinstance(data["body_storage"], str)
    ):
        raise ConformanceError("snapshot page contains invalid values")
    parent = data["parent_id"]
    if parent is not None and (
        not isinstance(parent, str) or not parent.isdigit()
    ):
        raise ConformanceError("snapshot page parent_id must be digits or null")
    version = data["version"]
    if version is not None and (
        not isinstance(version, int) or isinstance(version, bool)
    ):
        raise ConformanceError("snapshot page version must be an integer or null")
    return Page(
        page_id=page_id,
        title=data["title"],
        parent_id=parent,
        body_storage=data["body_storage"],
        status=data["status"],
        version=version,
    )


def excluded_page_from_snapshot(data: dict[str, Any]) -> ExcludedPage:
    required = {
        "id",
        "title",
        "parent_id",
        "type",
        "status",
        "depth",
        "excluded_subtree_root_id",
    }
    if set(data) != required or data.get("type") != "page":
        raise ConformanceError("excluded snapshot page uses an invalid schema")
    page_id = data["id"]
    parent_id = data["parent_id"]
    excluded_root = data["excluded_subtree_root_id"]
    depth = data["depth"]
    if (
        not isinstance(page_id, str)
        or not page_id.isdigit()
        or not isinstance(parent_id, str)
        or not parent_id.isdigit()
        or not isinstance(excluded_root, str)
        or not excluded_root.isdigit()
        or not isinstance(data["title"], str)
        or not isinstance(data["status"], str)
        or not isinstance(depth, int)
        or isinstance(depth, bool)
        or depth < 1
    ):
        raise ConformanceError("excluded snapshot page contains invalid values")
    return ExcludedPage(
        page_id=page_id,
        title=data["title"],
        parent_id=parent_id,
        status=data["status"],
        depth=depth,
        excluded_subtree_root_id=excluded_root,
    )


def delegated_page_from_snapshot(data: dict[str, Any]) -> DelegatedPage:
    required = {
        "id",
        "title",
        "parent_id",
        "type",
        "status",
        "depth",
        "delegated_subtree_root_id",
        "delegated_target_name",
    }
    if set(data) != required or data.get("type") != "page":
        raise ConformanceError("delegated snapshot page uses an invalid schema")
    page_id = data["id"]
    parent_id = data["parent_id"]
    delegated_root = data["delegated_subtree_root_id"]
    delegated_target = data["delegated_target_name"]
    depth = data["depth"]
    if (
        not isinstance(page_id, str)
        or not page_id.isdigit()
        or not isinstance(parent_id, str)
        or not parent_id.isdigit()
        or not isinstance(delegated_root, str)
        or not delegated_root.isdigit()
        or not isinstance(delegated_target, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", delegated_target)
        or not isinstance(data["title"], str)
        or not isinstance(data["status"], str)
        or not isinstance(depth, int)
        or isinstance(depth, bool)
        or depth < 1
    ):
        raise ConformanceError("delegated snapshot page contains invalid values")
    return DelegatedPage(
        page_id=page_id,
        title=data["title"],
        parent_id=parent_id,
        status=data["status"],
        depth=depth,
        delegated_subtree_root_id=delegated_root,
        delegated_target_name=delegated_target,
    )


def read_snapshot(path: Path) -> tuple[list[Tree], list[Alignment]]:
    payload = read_json(path)
    if payload.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise ConformanceError("snapshot schema_version is unsupported")
    raw_trees = payload.get("targets")
    if not isinstance(raw_trees, list) or not raw_trees:
        raise ConformanceError("snapshot requires a non-empty targets list")
    trees: list[Tree] = []
    for raw_tree in raw_trees:
        if not isinstance(raw_tree, dict):
            raise ConformanceError("snapshot targets must be objects")
        target_keys = {
            "name",
            "root_page_id",
            "profile",
            "traversal",
            "expected_page_count",
            "expected_non_page_count",
            "expected_content_count",
            "expected_decision_set",
            "namespace",
            "scope",
            "excluded_subtree_root_ids",
            "exclusion_authorities",
            "delegated_subtree_targets",
            "expected_classification_counts",
            "expected_non_page_classification_counts",
        }
        target = target_from_mapping(
            {key: raw_tree[key] for key in target_keys if key in raw_tree}
        )
        pages_data = raw_tree.get("pages")
        excluded_data = raw_tree.get("excluded_pages", [])
        delegated_data = raw_tree.get("delegated_pages", [])
        ignored_data = raw_tree.get("ignored_content", [])
        if (
            not isinstance(pages_data, list)
            or not isinstance(excluded_data, list)
            or not isinstance(delegated_data, list)
            or not isinstance(ignored_data, list)
        ):
            raise ConformanceError(f"snapshot target {target.name} has invalid page lists")
        pages = [page_from_snapshot(item) for item in pages_data if isinstance(item, dict)]
        if len(pages) != len(pages_data):
            raise ConformanceError(f"snapshot target {target.name} contains an invalid page")
        excluded_pages = [
            excluded_page_from_snapshot(item)
            for item in excluded_data
            if isinstance(item, dict)
        ]
        if len(excluded_pages) != len(excluded_data):
            raise ConformanceError(
                f"snapshot target {target.name} contains an invalid excluded page"
            )
        delegated_pages = [
            delegated_page_from_snapshot(item)
            for item in delegated_data
            if isinstance(item, dict)
        ]
        if len(delegated_pages) != len(delegated_data):
            raise ConformanceError(
                f"snapshot target {target.name} contains an invalid delegated page"
            )
        ignored: list[IgnoredContent] = []
        for item in ignored_data:
            required_ignored_keys = {
                "id",
                "type",
                "title",
                "parent_id",
                "depth",
                "classification",
                "classified_subtree_root_id",
                "delegated_target_name",
            }
            if not isinstance(item, dict) or set(item) != required_ignored_keys:
                raise ConformanceError(f"snapshot target {target.name} has invalid ignored content")
            content_id = item["id"]
            parent_id = item["parent_id"]
            depth = item["depth"]
            classification = item["classification"]
            classified_root = item["classified_subtree_root_id"]
            delegated_target = item["delegated_target_name"]
            if (
                not isinstance(content_id, str)
                or not content_id.isdigit()
                or not isinstance(parent_id, str)
                or not parent_id.isdigit()
                or not isinstance(item["type"], str)
                or not item["type"]
                or not isinstance(item["title"], str)
                or (
                    depth is not None
                    and (
                        not isinstance(depth, int)
                        or isinstance(depth, bool)
                        or depth < 1
                    )
                )
                or classification not in {"direct", "excluded", "delegated"}
                or (
                    classification == "direct"
                    and (classified_root is not None or delegated_target is not None)
                )
                or (
                    classification == "excluded"
                    and (
                        not isinstance(classified_root, str)
                        or not classified_root.isdigit()
                        or delegated_target is not None
                    )
                )
                or (
                    classification == "delegated"
                    and (
                        not isinstance(classified_root, str)
                        or not classified_root.isdigit()
                        or not isinstance(delegated_target, str)
                        or not re.fullmatch(
                            r"[a-z0-9][a-z0-9-]{1,63}", delegated_target
                        )
                    )
                )
            ):
                raise ConformanceError(
                    f"snapshot target {target.name} has invalid ignored content values"
                )
            ignored.append(
                IgnoredContent(
                    content_id=content_id,
                    content_type=item["type"],
                    title=item["title"],
                    parent_id=parent_id,
                    depth=depth,
                    classification=classification,
                    classified_subtree_root_id=classified_root,
                    delegated_target_name=delegated_target,
                )
            )
        trees.append(
            Tree(
                target=target,
                pages=pages,
                ignored_content=ignored,
                excluded_pages=excluded_pages,
                delegated_pages=delegated_pages,
            )
        )
    tree_names = [tree.target.name for tree in trees]
    if len(tree_names) != len(set(tree_names)):
        raise ConformanceError("snapshot target names must be unique")
    raw_alignments = payload.get("alignments", [])
    if not isinstance(raw_alignments, list) or any(
        not isinstance(item, dict) for item in raw_alignments
    ):
        raise ConformanceError("snapshot alignments must be a list of objects")
    target_names = {tree.target.name for tree in trees}
    alignments = [
        alignment_from_mapping(item, target_names) for item in raw_alignments
    ]
    return trees, alignments


def snapshot_payload(trees: Sequence[Tree], alignments: Sequence[Alignment]) -> dict[str, Any]:
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "targets": [tree.snapshot() for tree in trees],
        "alignments": [
            {
                "name": alignment.name,
                "template_target": alignment.template_target,
                "catalog_target": alignment.catalog_target,
                "product_source_artifacts": list(alignment.product_source_artifacts),
            }
            for alignment in alignments
        ],
    }


def safe_write(path: Path, content: str) -> None:
    path = path.expanduser()
    if ".." in path.parts:
        raise ConformanceError(f"refusing a parent-relative output path: {path}")
    path = path.absolute()
    if path.is_symlink():
        raise ConformanceError(f"refusing to overwrite symlink: {path}")
    for ancestor in path.parent.parents:
        if ancestor.is_symlink():
            raise ConformanceError(
                f"refusing to write through symlink ancestor: {ancestor}"
            )
    if path.parent.is_symlink():
        raise ConformanceError(f"refusing to write through symlink directory: {path.parent}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ConformanceError(f"refusing to write through symlink directory: {path.parent}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def finding_record(finding: Finding, redact_details: bool) -> dict[str, Any]:
    return {
        "severity": finding.severity,
        "code": finding.code,
        "target": finding.target,
        "message": (
            "Details are available only in the approved evidence store."
            if redact_details
            else finding.message
        ),
        "page_id": finding.page_id,
        "page_title": None if redact_details else finding.page_title,
    }


def tree_inventory_digest(tree: Tree) -> str:
    inventory = {
        "included_pages": sorted(
            (
                page.page_id,
                page.parent_id,
                page.title,
                page.status,
                page.version,
                sha256(page.body_storage.encode("utf-8")).hexdigest(),
            )
            for page in tree.pages
        ),
        "excluded_pages": sorted(
            (
                page.page_id,
                page.parent_id,
                page.title,
                page.status,
                page.depth,
                page.excluded_subtree_root_id,
            )
            for page in tree.excluded_pages
        ),
        "delegated_pages": sorted(
            (
                page.page_id,
                page.parent_id,
                page.title,
                page.status,
                page.depth,
                page.delegated_subtree_root_id,
                page.delegated_target_name,
            )
            for page in tree.delegated_pages
        ),
        "ignored_content": sorted(
            (
                item.content_id,
                item.parent_id,
                item.content_type,
                item.title,
                item.depth,
                item.classification,
                item.classified_subtree_root_id,
                item.delegated_target_name,
            )
            for item in tree.ignored_content
        ),
    }
    canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def cross_target_overlaps(trees: Sequence[Tree]) -> list[dict[str, Any]]:
    """Describe intentional target overlap without adding target row counts."""

    records: list[dict[str, Any]] = []
    for index, left in enumerate(trees):
        left_page_ids = {
            *(page.page_id for page in left.pages),
            *(page.page_id for page in left.excluded_pages),
            *(page.page_id for page in left.delegated_pages),
        }
        left_non_page_ids = {
            item.content_id for item in left.ignored_content
        }
        for right in trees[index + 1 :]:
            right_page_ids = {
                *(page.page_id for page in right.pages),
                *(page.page_id for page in right.excluded_pages),
                *(page.page_id for page in right.delegated_pages),
            }
            right_non_page_ids = {
                item.content_id for item in right.ignored_content
            }
            overlap_page_count = len(left_page_ids.intersection(right_page_ids))
            overlap_non_page_count = len(
                left_non_page_ids.intersection(right_non_page_ids)
            )
            if overlap_page_count == 0 and overlap_non_page_count == 0:
                continue
            left_delegation = next(
                (
                    item
                    for item in left.target.delegated_subtrees
                    if item.target_name == right.target.name
                ),
                None,
            )
            right_delegation = next(
                (
                    item
                    for item in right.target.delegated_subtrees
                    if item.target_name == left.target.name
                ),
                None,
            )
            if left_delegation is not None:
                primary, covering = left, right
                relationship = "delegated-coverage"
            elif right_delegation is not None:
                primary, covering = right, left
                relationship = "delegated-coverage"
            else:
                primary, covering = left, right
                relationship = "additional-validation"
            records.append(
                {
                    "primary_target": primary.target.name,
                    "covering_target": covering.target.name,
                    "relationship": relationship,
                    "overlap_page_count": overlap_page_count,
                    "overlap_non_page_count": overlap_non_page_count,
                    "overlap_content_count": (
                        overlap_page_count + overlap_non_page_count
                    ),
                }
            )
    return records


def build_report(
    trees: Sequence[Tree],
    findings: Sequence[Finding],
    *,
    redact_details: bool,
) -> dict[str, Any]:
    counts = {
        severity: sum(1 for finding in findings if finding.severity == severity)
        for severity in ("error", "warning", "info")
    }
    core = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "result": "fail" if counts["error"] else "pass",
        "counts": counts,
        "coverage_accounting": {
            "target_rows_are_additive": False,
            "cross_target_overlaps": cross_target_overlaps(trees),
        },
        "targets": [
            {
                "name": tree.target.name,
                "root_page_id": tree.target.root_page_id,
                "profile": tree.target.profile,
                "traversal": tree.target.traversal,
                "content_count": tree.content_count,
                "page_count": tree.page_count,
                "non_page_count": tree.non_page_count,
                "included_page_count": len(tree.pages) + len(tree.delegated_pages),
                "direct_validated_page_count": len(tree.pages),
                "delegated_page_count": len(tree.delegated_pages),
                "excluded_page_count": len(tree.excluded_pages),
                "expected_page_count": tree.target.expected_page_count,
                "expected_non_page_count": tree.target.expected_non_page_count,
                "expected_content_count": tree.target.expected_content_count,
                "expected_classification_counts": (
                    tree.target.expected_classification_counts.snapshot()
                    if tree.target.expected_classification_counts is not None
                    else None
                ),
                "non_page_classification_counts": (
                    tree.non_page_classification_counts().snapshot()
                ),
                "expected_non_page_classification_counts": (
                    tree.target.expected_non_page_classification_counts.snapshot()
                    if tree.target.expected_non_page_classification_counts is not None
                    else None
                ),
                "inventory_digest_sha256": tree_inventory_digest(tree),
                "exclusion_authorities": [
                    authority.snapshot()
                    for authority in tree.target.exclusion_authorities
                ],
                "excluded_subtrees": [
                    {
                        "root_page_id": root_id,
                        "page_count": page_count,
                        "non_page_count": tree.excluded_non_page_subtree_counts()[
                            root_id
                        ],
                        "content_count": (
                            page_count
                            + tree.excluded_non_page_subtree_counts()[root_id]
                        ),
                    }
                    for root_id, page_count in tree.excluded_subtree_counts().items()
                ],
                "delegated_subtrees": [
                    {
                        "root_page_id": root_id,
                        "target_name": target_name,
                        "page_count": page_count,
                        "non_page_count": (
                            tree.delegated_non_page_subtree_counts()[
                                (root_id, target_name)
                            ]
                        ),
                        "content_count": (
                            page_count
                            + tree.delegated_non_page_subtree_counts()[
                                (root_id, target_name)
                            ]
                        ),
                    }
                    for (root_id, target_name), page_count in (
                        tree.delegated_subtree_counts().items()
                    )
                ],
            }
            for tree in trees
        ],
        "findings": [finding_record(finding, redact_details) for finding in findings],
    }
    canonical = json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    core["evidence_digest_sha256"] = sha256(canonical.encode("utf-8")).hexdigest()
    return core


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# PGE Confluence Documentation Conformance",
        "",
        f"- Result: **{str(report['result']).upper()}**",
        f"- Errors: {report['counts']['error']}",
        f"- Warnings: {report['counts']['warning']}",
        f"- Information: {report['counts']['info']}",
        f"- Evidence digest: `{report['evidence_digest_sha256']}`",
        "",
        "## Targets",
        "",
        "Target rows are independent validation scopes and must not be summed.",
        "",
        "| Target | Content nodes | Pages | Non-page | Direct pages | Delegated pages | Excluded pages | Expected content | Expected pages | Expected non-page |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    excluded_sections: list[str] = []
    for target in report["targets"]:
        lines.append(
            f"| {target['name']} | {target['content_count']} | "
            f"{target['page_count']} | {target['non_page_count']} | "
            f"{target['direct_validated_page_count']} | "
            f"{target['delegated_page_count']} | {target['excluded_page_count']} | "
            f"{target['expected_content_count'] if target['expected_content_count'] is not None else 'n/a'} | "
            f"{target['expected_page_count'] if target['expected_page_count'] is not None else 'n/a'} | "
            f"{target['expected_non_page_count'] if target['expected_non_page_count'] is not None else 'n/a'} |"
        )
        if target["excluded_subtrees"]:
            excluded_sections.extend(
                [
                    "",
                    f"### Excluded subtrees: {target['name']}",
                    "",
                    "| Root page ID | Content nodes | Pages | Non-page |",
                    "| --- | ---: | ---: | ---: |",
                    *(
                        f"| {item['root_page_id']} | {item['content_count']} | "
                        f"{item['page_count']} | {item['non_page_count']} |"
                        for item in target["excluded_subtrees"]
                    ),
                ]
            )
        if target["delegated_subtrees"]:
            excluded_sections.extend(
                [
                    "",
                    f"### Delegated subtrees: {target['name']}",
                    "",
                    "| Root page ID | Covering target | Content nodes | Pages | Non-page |",
                    "| --- | --- | ---: | ---: | ---: |",
                    *(
                        f"| {item['root_page_id']} | {item['target_name']} | "
                        f"{item['content_count']} | {item['page_count']} | "
                        f"{item['non_page_count']} |"
                        for item in target["delegated_subtrees"]
                    ),
                ]
            )
    lines.extend(
        [
            "",
            "## Non-page classification",
            "",
            "| Target | Direct | Delegated | Disposition excluded | Total |",
            "| --- | ---: | ---: | ---: | ---: |",
            *(
                f"| {target['name']} | "
                f"{target['non_page_classification_counts']['direct']} | "
                f"{target['non_page_classification_counts']['delegated']} | "
                f"{target['non_page_classification_counts']['disposition_excluded']} | "
                f"{target['non_page_count']} |"
                for target in report["targets"]
            ),
        ]
    )
    lines.extend(excluded_sections)
    overlaps = report["coverage_accounting"]["cross_target_overlaps"]
    if overlaps:
        lines.extend(
            [
                "",
                "## Cross-target coverage",
                "",
                "| Primary target | Covering target | Relationship | Overlapping content | Overlapping pages | Overlapping non-page |",
                "| --- | --- | --- | ---: | ---: | ---: |",
                *(
                    f"| {item['primary_target']} | {item['covering_target']} | "
                    f"{item['relationship']} | {item['overlap_content_count']} | "
                    f"{item['overlap_page_count']} | "
                    f"{item['overlap_non_page_count']} |"
                    for item in overlaps
                ),
            ]
        )
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings.")
    else:
        lines.extend(
            [
                "| Severity | Code | Target | Page | Message |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for finding in report["findings"]:
            page = finding["page_id"] or "-"
            message = str(finding["message"]).replace("|", "\\|")
            lines.append(
                f"| {finding['severity']} | {finding['code']} | {finding['target']} | "
                f"{page} | {message} |"
            )
    return "\n".join(lines) + "\n"


def arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path, help="JSON target inventory for a live audit")
    source.add_argument("--snapshot", type=Path, help="deterministic snapshot to validate")
    source.add_argument("--root-page-id", help="single live root page ID")
    parser.add_argument("--target", action="append", default=[], help="configured target name")
    parser.add_argument("--profile", choices=sorted(ALLOWED_PROFILES))
    parser.add_argument("--expected-page-count", type=int)
    parser.add_argument("--expected-non-page-count", type=int)
    parser.add_argument("--expected-content-count", type=int)
    parser.add_argument("--expected-decision-set")
    parser.add_argument("--namespace")
    parser.add_argument("--scope")
    parser.add_argument("--snapshot-out", type=Path)
    parser.add_argument("--json-report", type=Path, required=True)
    parser.add_argument("--markdown-report", type=Path)
    parser.add_argument("--warnings-as-errors", action="store_true")
    parser.add_argument("--redact-details", action="store_true")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--request-timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args(argv)


def select_targets(
    targets: Sequence[Target],
    selected_names: Sequence[str],
) -> list[Target]:
    if not selected_names:
        return list(targets)
    if len(selected_names) != len(set(selected_names)):
        raise ConformanceError("target selector is duplicated")
    mapping = {target.name: target for target in targets}
    missing = sorted(set(selected_names) - set(mapping))
    if missing:
        raise ConformanceError(f"unknown target selector: {', '.join(missing)}")
    return [mapping[name] for name in selected_names]


def live_client(
    args: argparse.Namespace,
    allowed_origin: str = DEFAULT_ALLOWED_CONFLUENCE_ORIGIN,
) -> ConfluenceClient:
    return ConfluenceClient(
        os.environ.get("PGE_CONFLUENCE_BASE_URL", ""),
        os.environ.get("PGE_CONFLUENCE_USER_EMAIL", ""),
        os.environ.get("PGE_CONFLUENCE_API_TOKEN", ""),
        allowed_origin=allowed_origin,
        timeout=args.request_timeout,
    )


def run(argv: Sequence[str] | None = None) -> int:
    args = arguments(argv)
    if args.max_pages < 1 or args.max_pages > 50_000:
        raise ConformanceError("--max-pages must be between 1 and 50000")
    if args.request_timeout < 1 or args.request_timeout > 300:
        raise ConformanceError("--request-timeout must be between 1 and 300 seconds")

    if args.snapshot:
        trees, alignments = read_snapshot(args.snapshot)
        selected = {target.name for target in select_targets(
            [tree.target for tree in trees], args.target
        )}
        trees = [tree for tree in trees if tree.target.name in selected]
    else:
        if args.config:
            allowed_origin, targets, alignments = read_config(args.config)
            targets = select_targets(targets, args.target)
        else:
            allowed_origin = DEFAULT_ALLOWED_CONFLUENCE_ORIGIN
            if not args.profile:
                raise ConformanceError("--profile is required with --root-page-id")
            target = Target(
                name="single-root",
                root_page_id=str(args.root_page_id),
                profile=args.profile,
                traversal="recursive",
                expected_page_count=args.expected_page_count,
                expected_non_page_count=args.expected_non_page_count,
                expected_content_count=args.expected_content_count,
                expected_decision_set=args.expected_decision_set,
                namespace=args.namespace,
                scope=args.scope,
            )
            target.validate()
            targets = [target]
            alignments = []
        client = live_client(args, allowed_origin)
        trees = [crawl_tree(client, target, args.max_pages) for target in targets]

    selected_tree_names = {tree.target.name for tree in trees}
    alignments = [
        alignment
        for alignment in alignments
        if alignment.template_target in selected_tree_names
        and alignment.catalog_target in selected_tree_names
    ]
    if args.snapshot_out:
        safe_write(
            args.snapshot_out,
            json.dumps(
                snapshot_payload(trees, alignments),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )

    all_findings: list[Finding] = []
    parsers: dict[str, dict[str, StorageParser]] = {}
    tree_map = {tree.target.name: tree for tree in trees}
    for tree in trees:
        findings, target_parsers = validate_tree(tree)
        all_findings.extend(findings)
        parsers[tree.target.name] = target_parsers
    all_findings.extend(validate_delegated_coverage(trees))
    for alignment in alignments:
        all_findings.extend(validate_alignment(alignment, tree_map, parsers))
    if args.warnings_as_errors:
        all_findings = [
            Finding(
                severity="error" if finding.severity == "warning" else finding.severity,
                code=finding.code,
                target=finding.target,
                message=finding.message,
                page_id=finding.page_id,
                page_title=finding.page_title,
            )
            for finding in all_findings
        ]
    all_findings.sort(
        key=lambda finding: (
            {"error": 0, "warning": 1, "info": 2}.get(finding.severity, 3),
            finding.target,
            finding.page_id or "",
            finding.code,
        )
    )
    report = build_report(trees, all_findings, redact_details=args.redact_details)
    safe_write(
        args.json_report,
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    if args.markdown_report:
        safe_write(args.markdown_report, markdown_report(report))
    print(
        "PGE Confluence conformance: "
        f"{report['result']} "
        f"({report['counts']['error']} errors, "
        f"{report['counts']['warning']} warnings, "
        f"{report['counts']['info']} informational findings)"
    )
    return 1 if report["counts"]["error"] else 0


def main() -> int:
    try:
        return run()
    except ConformanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
