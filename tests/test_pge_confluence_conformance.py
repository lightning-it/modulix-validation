"""Unit and contract tests for the PGE Confluence conformance validator."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "pge-confluence-conformance.py"
SPEC = importlib.util.spec_from_file_location("pge_confluence_conformance", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {SCRIPT}")
PGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PGE
SPEC.loader.exec_module(PGE)


def bold(value: str) -> str:
    return f"<strong>{value}</strong>"


def metadata_table(values: dict[str, str], *, explicit_bold: bool = True) -> str:
    decorate = bold if explicit_bold else (lambda value: value)
    rows = [
        "<tr>"
        f"<th>{decorate('Field')}</th>"
        f"<th>{decorate('Value')}</th>"
        "</tr>"
    ]
    rows.extend(
        "<tr>"
        f"<td>{decorate(key)}</td>"
        f"<td>{value}</td>"
        "</tr>"
        for key, value in values.items()
    )
    return "<table>" + "".join(rows) + "</table>"


def product_metadata(**overrides: str) -> dict[str, str]:
    values = {
        "Document ID": "PGE-DOC-001",
        "Status": "Active",
        "Version": "1.0",
        "Owner": "PGE Product Owner",
        "Reviewer": "PGE Reviewer",
        "Classification": "Internal",
        "Scope": "PGE documentation",
        "Leading Source": "Confluence",
        "Documentation Standard": "PGE-DEC-036",
        "Documentation Conformance": "Conformant",
    }
    values.update(overrides)
    return values


def decision_metadata(decision_id: str, **overrides: str) -> dict[str, str]:
    values = {
        "Decision ID": decision_id,
        "Decision Status": "Accepted",
        "Version": "1.0",
        "Decision Date": "2026-08-08",
        "Decision Owner": "PGE Product Owner",
        "Approver": "PGE Product Owner",
        "Reviewer Note": "Owner acceptance recorded",
        "Classification": "Internal",
        "Scope": "PGE product",
        "Documentation Standard": "PGE-DEC-036",
        "Documentation Conformance": "Conformant",
    }
    values.update(overrides)
    return values


def engagement_metadata(**overrides: str) -> dict[str, str]:
    values = {
        "Document ID": "LIT-PIS-001",
        "Engagement ID": "LIT-PIS",
        "Customer / Assessment Entity": "Lightning IT",
        "Engagement Scope": "Platform and Infrastructure Services",
        "Scope Target": "LIT-PIS",
        "Engagement Owner": "Engagement Owner",
        "Engagement Reviewer": "Engagement Reviewer",
        "Documentation Architecture": "Engagement Documentation Architecture",
        "PGE Delivery Mode": "Full",
        "Status": "Active",
        "Classification": "Internal",
        "Version": "1.0",
    }
    values.update(overrides)
    return values


def chapters(
    *,
    toc_title: str = "00 Inhaltsverzeichnis",
    second_title: str = "01 Purpose",
    include_expand: bool = True,
    include_closing_rules: bool = True,
    include_h3: bool = False,
) -> str:
    toc = ""
    if include_expand:
        toc = (
            '<ac:structured-macro ac:name="expand">'
            "<ac:rich-text-body>"
            '<ac:structured-macro ac:name="toc" />'
            "</ac:rich-text-body>"
            "</ac:structured-macro>"
        )
    close = "<hr />" if include_closing_rules else ""
    body = f"<h2>{toc_title}</h2>{toc}{close}<h2>{second_title}</h2>"
    if include_h3:
        body += "<h3>01.01 Detail</h3><p>Controlled detail.</p>"
    else:
        body += "<p>Controlled purpose.</p>"
    return body + close


def storage(
    title: str,
    metadata: dict[str, str],
    *,
    h1_title: str | None = None,
    extra: str = "",
    explicit_bold: bool = True,
    chapter_content: str | None = None,
) -> str:
    return (
        f"<h1>{h1_title or title}</h1>"
        + metadata_table(metadata, explicit_bold=explicit_bold)
        + (chapter_content if chapter_content is not None else chapters())
        + extra
    )


def page(
    page_id: str,
    title: str,
    metadata: dict[str, str],
    *,
    parent_id: str | None = None,
    h1_title: str | None = None,
    extra: str = "",
    explicit_bold: bool = True,
    chapter_content: str | None = None,
) -> PGE.Page:
    return PGE.Page(
        page_id=page_id,
        title=title,
        parent_id=parent_id,
        body_storage=storage(
            title,
            metadata,
            h1_title=h1_title,
            extra=extra,
            explicit_bold=explicit_bold,
            chapter_content=chapter_content,
        ),
        status="current",
        version=1,
    )


def target(
    profile: str = "product",
    **overrides: object,
) -> PGE.Target:
    values: dict[str, object] = {
        "name": "test-target",
        "root_page_id": "1",
        "profile": profile,
    }
    values.update(overrides)
    return PGE.Target(**values)


class StructureTests(unittest.TestCase):
    def test_fully_conformant_page_passes_structure_metadata_and_table_rules(self) -> None:
        current = page("1", "Product Documentation", product_metadata())
        tree = PGE.Tree(target=target(), pages=[current])

        findings, _ = PGE.validate_tree(tree)

        self.assertEqual([], [finding for finding in findings if finding.severity == "error"])

    def test_product_h1_must_exactly_match_the_confluence_title(self) -> None:
        current = page(
            "1",
            "Architecture and Controls",
            product_metadata(),
            h1_title="Architecture Controls",
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target(), [current]))

        self.assertIn("heading.h1-title", {item.code for item in findings})

    def test_header_cells_must_be_explicitly_bold_not_merely_th_cells(self) -> None:
        current = page(
            "1",
            "Product Documentation",
            product_metadata(),
            explicit_bold=False,
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target=target(), pages=[current]))

        codes = [finding.code for finding in findings]
        self.assertIn("table.header-bold", codes)
        self.assertIn("table.field-bold", codes)

    def test_exact_toc_title_contiguous_numbers_and_associated_expand_are_required(self) -> None:
        current = page(
            "1",
            "Product Documentation",
            product_metadata(),
            chapter_content=chapters(
                toc_title="00 Contents",
                second_title="02 Purpose",
                include_expand=False,
            ),
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target=target(), pages=[current]))

        codes = {finding.code for finding in findings}
        self.assertIn("heading.toc-title", codes)
        self.assertIn("heading.h2-sequence", codes)
        self.assertIn("heading.toc-expand", codes)

    def test_h3_numbers_must_match_parent_and_remain_contiguous(self) -> None:
        malformed = (
            "<h2>00 Inhaltsverzeichnis</h2>"
            '<ac:structured-macro ac:name="expand"><ac:rich-text-body>'
            '<ac:structured-macro ac:name="toc" />'
            "</ac:rich-text-body></ac:structured-macro><hr />"
            "<h2>01 Purpose</h2>"
            "<h3>02.02 Detail</h3><p>Detail.</p><hr />"
        )
        current = page(
            "1",
            "Product Documentation",
            product_metadata(),
            chapter_content=malformed,
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target=target(), pages=[current]))

        codes = {finding.code for finding in findings}
        self.assertIn("heading.h3-parent", codes)
        self.assertIn("heading.h3-sequence", codes)

    def test_every_h2_chapter_requires_a_final_horizontal_rule(self) -> None:
        current = page(
            "1",
            "Product Documentation",
            product_metadata(),
            chapter_content=chapters(include_closing_rules=False, include_h3=True),
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target=target(), pages=[current]))

        closing = [finding for finding in findings if finding.code == "heading.chapter-close"]
        self.assertGreaterEqual(len(closing), 2)

    def test_h3_does_not_require_an_independent_horizontal_rule(self) -> None:
        current = page(
            "1",
            "Product Documentation",
            product_metadata(),
            chapter_content=chapters(include_h3=True),
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target=target(), pages=[current]))

        self.assertNotIn(
            "heading.chapter-close", {finding.code for finding in findings}
        )


class MetadataAndContentTests(unittest.TestCase):
    def test_duplicate_normalized_metadata_field_is_rejected(self) -> None:
        body = storage("Product Documentation", product_metadata()).replace(
            "</table>",
            f"<tr><td>{bold('Status')}</td><td>Active</td></tr></table>",
            1,
        )
        current = PGE.Page(
            page_id="1",
            title="Product Documentation",
            parent_id=None,
            body_storage=body,
            status="current",
            version=1,
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target(), [current]))

        self.assertIn("metadata.duplicate-field", {item.code for item in findings})

    def test_blank_required_metadata_and_uncontrolled_values_fail(self) -> None:
        current = page(
            "1",
            "Product Documentation",
            product_metadata(
                Owner="",
                Status="Almost ready",
                Classification="Lightning IT Internal",
                Version="latest",
                **{"Documentation Conformance": "Pending"},
            ),
        )

        findings, _ = PGE.validate_tree(PGE.Tree(target=target(), pages=[current]))

        codes = {finding.code for finding in findings}
        self.assertTrue(
            {
                "metadata.required",
                "metadata.status",
                "metadata.classification",
                "metadata.version",
                "metadata.conformance",
            }.issubset(codes)
        )

    def test_hidden_markers_are_always_forbidden(self) -> None:
        current = page(
            "1",
            "PGE Template Library",
            product_metadata(),
            extra="<!-- migration-complete -->",
        )
        template_target = target(profile="template")

        findings, _ = PGE.validate_tree(PGE.Tree(target=template_target, pages=[current]))

        self.assertIn("content.hidden-marker", {finding.code for finding in findings})

    def test_placeholder_is_allowed_only_on_declared_template_page(self) -> None:
        declared = page(
            "1",
            "Architecture Template",
            product_metadata(),
            extra="<p>{{ architecture_owner }}</p>",
        )
        undeclared = page(
            "1",
            "Architecture Guidance",
            product_metadata(),
            extra="<p>{{ architecture_owner }}</p>",
        )
        template_target = target(profile="template")

        declared_findings, _ = PGE.validate_tree(
            PGE.Tree(target=template_target, pages=[declared])
        )
        undeclared_findings, _ = PGE.validate_tree(
            PGE.Tree(target=template_target, pages=[undeclared])
        )

        self.assertNotIn(
            "content.placeholder", {finding.code for finding in declared_findings}
        )
        self.assertIn(
            "content.placeholder", {finding.code for finding in undeclared_findings}
        )


class DecisionSetTests(unittest.TestCase):
    def test_readable_title_is_recognized_from_decision_id_metadata(self) -> None:
        current = page(
            "2",
            "Control Tailoring and Inheritance",
            decision_metadata("PGE-DEC-001"),
            parent_id="1",
        )
        findings, _ = PGE.validate_tree(
            PGE.Tree(
                target=target(expected_decision_set="001"),
                pages=[
                    page("1", "Product Decision Records", product_metadata()),
                    current,
                ],
            )
        )

        decision_errors = [
            finding
            for finding in findings
            if finding.severity == "error" and finding.code.startswith("decision.")
        ]
        self.assertEqual([], decision_errors)

    def test_missing_unexpected_invalid_and_title_conflicting_decisions_fail(self) -> None:
        decision_one = page(
            "2",
            "PGE-DEC-001 - First Decision",
            decision_metadata("PGE-DEC-999"),
            parent_id="1",
        )
        unexpected = page(
            "3",
            "PGE-DEC-003 - Unexpected Decision",
            decision_metadata("PGE-DEC-003"),
            parent_id="1",
        )
        invalid = page(
            "4",
            "PGE-DEC-XX - Invalid Decision",
            product_metadata(),
            parent_id="1",
        )
        tree = PGE.Tree(
            target=target(expected_decision_set="001-002"),
            pages=[
                page("1", "Product Decision Records", product_metadata()),
                decision_one,
                unexpected,
                invalid,
            ],
        )

        findings, _ = PGE.validate_tree(tree)

        codes = {finding.code for finding in findings}
        self.assertTrue(
            {
                "decision.title-metadata-conflict",
                "decision.missing",
                "decision.unexpected",
                "decision.invalid-title-id",
            }.issubset(codes)
        )

    def test_duplicate_and_malformed_metadata_ids_fail_closed(self) -> None:
        tree = PGE.Tree(
            target=target(expected_decision_set="001-002"),
            pages=[
                page("1", "Product Decision Records", product_metadata()),
                page(
                    "2",
                    "Readable First Decision",
                    decision_metadata("PGE-DEC-001"),
                    parent_id="1",
                ),
                page(
                    "3",
                    "Duplicate First Decision",
                    decision_metadata("PGE-DEC-001"),
                    parent_id="1",
                ),
                page(
                    "4",
                    "Malformed Decision",
                    decision_metadata("PGE-DEC-X02"),
                    parent_id="1",
                ),
            ],
        )

        findings, _ = PGE.validate_tree(tree)
        codes = {finding.code for finding in findings}

        self.assertTrue(
            {
                "decision.duplicate",
                "decision.invalid-id",
                "decision.missing",
            }.issubset(codes)
        )

    def test_decision_set_parser_rejects_zero_reversed_and_malformed_ranges(self) -> None:
        for value in ("000", "003-001", "1-003", "001,,002"):
            with self.subTest(value=value):
                with self.assertRaises(PGE.ConformanceError):
                    PGE.parse_decision_set(value)


class EngagementNamingTests(unittest.TestCase):
    def tree(self, grandchild_title: str) -> PGE.Tree:
        engagement_target = target(
            profile="engagement",
            root_page_id="1",
            namespace="LIT",
            scope="PIS",
        )
        return PGE.Tree(
            target=engagement_target,
            pages=[
                page(
                    "1",
                    "LIT-Platform-and-Infrastructure-Services",
                    engagement_metadata(),
                    h1_title="Platform & Infrastructure Services",
                ),
                page(
                    "2",
                    "LIT-PIS-10-Scope-and-Requirement",
                    engagement_metadata(),
                    parent_id="1",
                    h1_title="Scope and Requirement",
                ),
                page(
                    "3",
                    grandchild_title,
                    engagement_metadata(),
                    parent_id="2",
                    h1_title="Engagement Baseline Manifest",
                ),
            ],
        )

    def test_code_is_derived_from_parent_descriptor_and_inherited(self) -> None:
        findings, _ = PGE.validate_tree(
            self.tree("LIT-PIS-SRE-10-Engagement-Baseline-Manifest")
        )

        self.assertNotIn(
            "naming.inherited-code", {finding.code for finding in findings}
        )

    def test_wrong_or_two_letter_inherited_code_fails(self) -> None:
        findings, _ = PGE.validate_tree(
            self.tree("LIT-PIS-SR-10-Engagement-Baseline-Manifest")
        )

        self.assertIn("naming.format", {finding.code for finding in findings})

    def test_area_code_algorithm_ignores_connectors_and_uses_three_letters(self) -> None:
        self.assertEqual("SRE", PGE.derive_area_code("Scope-and-Requirement"))
        self.assertEqual("EBM", PGE.derive_area_code("Engagement-Baseline-Manifest"))
        self.assertEqual("ARC", PGE.derive_area_code("Architecture"))
        self.assertEqual("NIN", PGE.derive_area_code("Network-and-Integration"))

    def test_root_must_not_contain_scope_or_number(self) -> None:
        tree = self.tree("LIT-PIS-SRE-10-Engagement-Baseline-Manifest")
        tree.pages[0] = page(
            "1",
            "LIT-PIS-00-Platform-and-Infrastructure-Services",
            engagement_metadata(),
            h1_title="Platform and Infrastructure Services",
        )

        findings, _ = PGE.validate_tree(tree)

        self.assertIn("naming.root", {finding.code for finding in findings})

    def test_three_digit_order_number_is_rejected(self) -> None:
        tree = self.tree("LIT-PIS-SRE-10-Engagement-Baseline-Manifest")
        tree.pages[1] = page(
            "2",
            "LIT-PIS-100-Scope-and-Requirement",
            engagement_metadata(),
            parent_id="1",
            h1_title="Scope and Requirement",
        )

        findings, _ = PGE.validate_tree(tree)

        self.assertIn("naming.format", {finding.code for finding in findings})

    def test_engagement_h1_must_be_readable_content_title(self) -> None:
        tree = self.tree("LIT-PIS-SRE-10-Engagement-Baseline-Manifest")
        tree.pages[1] = page(
            "2",
            "LIT-PIS-10-Scope-and-Requirement",
            engagement_metadata(),
            parent_id="1",
        )

        findings, _ = PGE.validate_tree(tree)

        self.assertIn("heading.h1-title", {finding.code for finding in findings})


def artifact_table(records: list[tuple[str, str, str]]) -> str:
    rows = [
        "<tr>"
        f"<th>{bold('Artifact Type')}</th>"
        f"<th>{bold('Status')}</th>"
        f"<th>{bold('Baseline')}</th>"
        f"<th>{bold('Canonical Template or Product Source')}</th>"
        "</tr>"
    ]
    rows.extend(
        f"<tr><td>{name}</td><td>{status}</td><td>{baseline}</td>"
        f'<td><a href="/wiki/spaces/LIT/pages/1">Template Library</a></td></tr>'
        for name, status, baseline in records
    )
    return "<table>" + "".join(rows) + "</table>"


class ArtifactAlignmentTests(unittest.TestCase):
    def alignment(
        self,
        template_records: list[tuple[str, str, str]],
        catalog_records: list[tuple[str, str, str]],
    ) -> tuple[PGE.Alignment, dict[str, PGE.Tree], dict[str, dict[str, PGE.StorageParser]]]:
        template_target = target(name="templates", profile="template", root_page_id="1")
        catalog_target = target(name="catalog", profile="product", root_page_id="2")
        template_page = page(
            "1",
            "Template Library",
            product_metadata(),
            extra=artifact_table(template_records),
        )
        catalog_page = page(
            "2",
            "Artifact Catalog",
            product_metadata(),
            extra=artifact_table(catalog_records),
        )
        trees = {
            "templates": PGE.Tree(template_target, [template_page]),
            "catalog": PGE.Tree(catalog_target, [catalog_page]),
        }
        parsers = {
            name: {
                tree.pages[0].page_id: PGE.parse_storage(tree.pages[0].body_storage)
            }
            for name, tree in trees.items()
        }
        return PGE.Alignment("alignment", "templates", "catalog"), trees, parsers

    def test_current_artifact_sets_align(self) -> None:
        alignment, trees, parsers = self.alignment(
            [("Architecture", "Active", "Yes")],
            [("Architecture", "Active", "Yes")],
        )

        findings = PGE.validate_alignment(alignment, trees, parsers)

        self.assertEqual([], findings)

    def test_missing_mapping_and_proposed_baseline_fail(self) -> None:
        alignment, trees, parsers = self.alignment(
            [("Architecture", "Proposed", "Yes")],
            [("Assessment Report", "Active", "Yes")],
        )

        findings = PGE.validate_alignment(alignment, trees, parsers)

        codes = {finding.code for finding in findings}
        self.assertTrue(
            {
                "alignment.proposed-baseline",
                "alignment.template-missing",
            }.issubset(codes)
        )

    def test_template_artifacts_are_derived_from_numbered_template_headings(self) -> None:
        template_target = target(name="templates", profile="template", root_page_id="1")
        title = "Architecture Templates"
        current = page(
            "1",
            title,
            {
                **product_metadata(),
                "Template-Set-ID / Version": "PGE-TPL-ARC-001 / 1.0",
                "Template-Status": "Current",
            },
            chapter_content=(
                "<h2>00 Inhaltsverzeichnis</h2>"
                '<ac:structured-macro ac:name="expand"><ac:rich-text-body>'
                '<ac:structured-macro ac:name="toc" />'
                "</ac:rich-text-body></ac:structured-macro><hr />"
                "<h2>01 Vorlage: Architecture Overview</h2>"
                "<p>{{ architecture }}</p><hr />"
            ),
        )
        parser = PGE.parse_storage(current.body_storage)

        records = PGE.artifact_records(
            PGE.Tree(template_target, [current]),
            {"1": parser},
        )

        self.assertIn("architecture overview", {record.name for record in records})


class TraversalTests(unittest.TestCase):
    class FakeClient:
        def __init__(self, pages: dict[str, PGE.Page], children: dict[str, tuple[list[dict[str, str]], list[PGE.IgnoredContent]]]):
            self.pages = pages
            self.children = children

        def page(self, page_id: str) -> PGE.Page:
            return self.pages[page_id]

        def direct_children(self, page_id: str) -> tuple[list[dict[str, str]], list[PGE.IgnoredContent]]:
            return self.children.get(page_id, ([], []))

    def test_recursive_traversal_is_complete_and_reports_non_page_content(self) -> None:
        pages = {
            "1": page("1", "Root", product_metadata()),
            "2": page("2", "Child", product_metadata(), parent_id="1"),
            "3": page("3", "Grandchild", product_metadata(), parent_id="2"),
        }
        children = {
            "1": (
                [{"id": "2", "type": "page"}],
                [PGE.IgnoredContent("99", "whiteboard", "Board", "1")],
            ),
            "2": ([{"id": "3", "type": "page"}], []),
        }
        current_target = target(expected_page_count=3)

        tree = PGE.crawl_tree(self.FakeClient(pages, children), current_target, 10)
        findings, _ = PGE.validate_tree(tree)

        self.assertEqual(["1", "2", "3"], [item.page_id for item in tree.pages])
        self.assertEqual(["99"], [item.content_id for item in tree.ignored_content])
        self.assertIn("tree.non-page-ignored", {finding.code for finding in findings})
        self.assertNotIn("tree.page-count", {finding.code for finding in findings})

    def test_page_only_traversal_does_not_enumerate_children(self) -> None:
        root = page("1", "Root", product_metadata())
        fake = self.FakeClient({"1": root}, {})
        fake.direct_children = mock.Mock(side_effect=AssertionError("must not traverse"))
        current_target = target(traversal="page-only", expected_page_count=1)

        tree = PGE.crawl_tree(fake, current_target, 10)

        self.assertEqual(["1"], [item.page_id for item in tree.pages])
        fake.direct_children.assert_not_called()

    def test_classified_traversal_covers_pages_below_non_page_containers(self) -> None:
        current_target = target(
            root_page_id="1",
            excluded_subtree_root_ids=("3",),
            exclusion_authorities=(PGE.ExclusionAuthority("1", 1),),
        )
        pages = {
            "1": page("1", "Root", product_metadata()),
            "2": page("2", "Included", product_metadata(), parent_id="1"),
            "5": page("5", "Nested Included", product_metadata(), parent_id="9"),
        }
        fake = self.FakeClient(pages, {})
        fake.page = mock.Mock(side_effect=lambda page_id: pages[page_id])
        fake.descendants = mock.Mock(
            return_value=(
                [
                    {
                        "id": "2",
                        "type": "page",
                        "title": "Included",
                        "parentId": "1",
                        "status": "current",
                        "depth": 1,
                    },
                    {
                        "id": "5",
                        "type": "page",
                        "title": "Nested Included",
                        "parentId": "9",
                        "status": "current",
                        "depth": 3,
                    },
                    {
                        "id": "3",
                        "type": "page",
                        "title": "Retained Root",
                        "parentId": "1",
                        "status": "current",
                        "depth": 1,
                    },
                    {
                        "id": "4",
                        "type": "page",
                        "title": "Retained Child",
                        "parentId": "3",
                        "status": "current",
                        "depth": 2,
                    },
                ],
                [PGE.IgnoredContent("9", "folder", "Folder", "2")],
            )
        )

        tree = PGE.crawl_tree(fake, current_target, 10)
        findings, _ = PGE.validate_tree(tree)
        report = PGE.build_report([tree], findings, redact_details=True)

        self.assertEqual(["1", "2", "5"], [item.page_id for item in tree.pages])
        self.assertEqual(["3", "4"], [item.page_id for item in tree.excluded_pages])
        self.assertEqual({"3": 2}, tree.excluded_subtree_counts())
        self.assertEqual([mock.call("1"), mock.call("2"), mock.call("5")], fake.page.call_args_list)
        self.assertNotIn("tree.classification", {finding.code for finding in findings})
        self.assertEqual(5, report["targets"][0]["page_count"])
        self.assertEqual(3, report["targets"][0]["included_page_count"])
        self.assertEqual(2, report["targets"][0]["excluded_page_count"])
        self.assertEqual(
            [{"root_page_id": "3", "page_count": 2}],
            report["targets"][0]["excluded_subtrees"],
        )
        self.assertRegex(report["targets"][0]["inventory_digest_sha256"], r"^[0-9a-f]{64}$")

    def test_delegated_subtree_is_not_fetched_and_requires_exact_target_coverage(self) -> None:
        source_target = target(
            root_page_id="1",
            delegated_subtrees=(PGE.DelegatedSubtree("2", "coverage-target"),),
        )
        source_pages = {
            "1": page("1", "Root", product_metadata()),
            "4": page("4", "Direct", product_metadata(), parent_id="1"),
        }
        fake = self.FakeClient(source_pages, {})
        fake.page = mock.Mock(side_effect=lambda page_id: source_pages[page_id])
        fake.descendants = mock.Mock(
            return_value=(
                [
                    {
                        "id": "2",
                        "type": "page",
                        "title": "Delegated Root",
                        "parentId": "1",
                        "status": "current",
                        "depth": 1,
                    },
                    {
                        "id": "3",
                        "type": "page",
                        "title": "Delegated Child",
                        "parentId": "2",
                        "status": "current",
                        "depth": 2,
                    },
                    {
                        "id": "4",
                        "type": "page",
                        "title": "Direct",
                        "parentId": "1",
                        "status": "current",
                        "depth": 1,
                    },
                ],
                [],
            )
        )

        source_tree = PGE.crawl_tree(fake, source_target, 10)
        coverage_tree = PGE.Tree(
            target=PGE.Target(
                name="coverage-target",
                root_page_id="2",
                profile="product",
                expected_page_count=2,
            ),
            pages=[
                page("2", "Delegated Root", product_metadata(), parent_id="1"),
                page("3", "Delegated Child", product_metadata(), parent_id="2"),
            ],
        )
        report = PGE.build_report([source_tree, coverage_tree], [], redact_details=True)
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "delegated-snapshot.json"
            snapshot.write_text(
                json.dumps(PGE.snapshot_payload([source_tree, coverage_tree], [])),
                encoding="utf-8",
            )
            snapshot_trees, _ = PGE.read_snapshot(snapshot)

        self.assertEqual([mock.call("1"), mock.call("4")], fake.page.call_args_list)
        self.assertEqual(["2", "3"], [page.page_id for page in source_tree.delegated_pages])
        self.assertEqual([], PGE.validate_delegated_coverage([source_tree, coverage_tree]))
        self.assertEqual([], PGE.validate_delegated_coverage(snapshot_trees))
        missing = PGE.validate_delegated_coverage([source_tree])
        self.assertEqual(["tree.delegated-target-missing"], [item.code for item in missing])
        self.assertEqual(4, report["targets"][0]["page_count"])
        self.assertEqual(2, report["targets"][0]["direct_validated_page_count"])
        self.assertEqual(2, report["targets"][0]["delegated_page_count"])
        self.assertEqual(
            [
                {
                    "root_page_id": "2",
                    "target_name": "coverage-target",
                    "page_count": 2,
                }
            ],
            report["targets"][0]["delegated_subtrees"],
        )
        self.assertEqual(
            [
                {
                    "primary_target": "test-target",
                    "covering_target": "coverage-target",
                    "relationship": "delegated-coverage",
                    "overlap_page_count": 2,
                }
            ],
            report["coverage_accounting"]["cross_target_overlaps"],
        )

    def test_nested_excluded_roots_use_the_most_specific_disposition(self) -> None:
        current_target = target(
            root_page_id="1",
            excluded_subtree_root_ids=("2", "3"),
            exclusion_authorities=(PGE.ExclusionAuthority("1", 1),),
        )
        pages = {"1": page("1", "Root", product_metadata())}
        fake = self.FakeClient(pages, {})
        fake.descendants = mock.Mock(
            return_value=(
                [
                    {
                        "id": "2",
                        "type": "page",
                        "title": "Excluded",
                        "parentId": "1",
                        "status": "current",
                        "depth": 1,
                    },
                    {
                        "id": "3",
                        "type": "page",
                        "title": "Nested Excluded",
                        "parentId": "2",
                        "status": "current",
                        "depth": 2,
                    },
                    {
                        "id": "4",
                        "type": "page",
                        "title": "Nested Child",
                        "parentId": "3",
                        "status": "current",
                        "depth": 3,
                    },
                ],
                [],
            )
        )

        tree = PGE.crawl_tree(fake, current_target, 10)
        findings, _ = PGE.validate_tree(tree)

        self.assertEqual(
            [("2", "2"), ("3", "3"), ("4", "3")],
            [
                (page.page_id, page.excluded_subtree_root_id)
                for page in tree.excluded_pages
            ],
        )
        self.assertEqual({"2": 1, "3": 2}, tree.excluded_subtree_counts())
        self.assertNotIn("tree.classification", {finding.code for finding in findings})

    def test_expected_page_count_detects_incomplete_snapshot(self) -> None:
        current_target = target(expected_page_count=2)
        findings, _ = PGE.validate_tree(
            PGE.Tree(current_target, [page("1", "Root", product_metadata())])
        )
        self.assertIn("tree.page-count", {finding.code for finding in findings})

    def test_expected_classification_counts_detect_disposition_drift(self) -> None:
        current_target = target(
            expected_page_count=1,
            expected_classification_counts=PGE.ClassificationCounts(
                direct_validated=0,
                delegated=0,
                disposition_excluded=1,
            ),
        )
        findings, _ = PGE.validate_tree(
            PGE.Tree(current_target, [page("1", "Root", product_metadata())])
        )

        self.assertIn("tree.classification-count", {item.code for item in findings})

    def test_pagination_consumes_every_cursor_and_rejects_cursor_cycles(self) -> None:
        client = object.__new__(PGE.ConfluenceClient)
        responses = [
            {
                "results": [{"id": "2", "type": "page", "title": "Child"}],
                "_links": {"next": "/wiki/api/v2/pages/1/direct-children?cursor=abc"},
            },
            {
                "results": [{"id": "3", "type": "whiteboard", "title": "Board"}],
                "_links": {},
            },
        ]
        client._get_json = mock.Mock(side_effect=responses)

        children, ignored = client.direct_children("1")

        self.assertEqual(["2"], [item["id"] for item in children])
        self.assertEqual(["3"], [item.content_id for item in ignored])
        self.assertEqual("abc", client._get_json.call_args_list[1].args[1]["cursor"])

        cycling = object.__new__(PGE.ConfluenceClient)
        cycling._get_json = mock.Mock(
            side_effect=[
                {"results": [], "_links": {"next": "?cursor=repeat"}},
                {"results": [], "_links": {"next": "?cursor=repeat"}},
            ]
        )
        with self.assertRaisesRegex(PGE.ConformanceError, "cursor repeated"):
            cycling.direct_children("1")

    def test_descendant_inventory_paginates_and_keeps_non_page_parents(self) -> None:
        client = object.__new__(PGE.ConfluenceClient)
        client._get_json = mock.Mock(
            side_effect=[
                {
                    "results": [
                        {
                            "id": "2",
                            "type": "page",
                            "title": "Page",
                            "parentId": "1",
                            "depth": 1,
                        }
                    ],
                    "_links": {"next": "?cursor=next"},
                },
                {
                    "results": [
                        {
                            "id": "9",
                            "type": "embed",
                            "title": "Embed",
                            "parentId": "2",
                            "depth": 2,
                        }
                    ],
                    "_links": {},
                },
            ]
        )

        pages, ignored = client.descendants("1", 10)

        self.assertEqual(["2"], [str(item["id"]) for item in pages])
        self.assertEqual(["9"], [item.content_id for item in ignored])
        self.assertEqual("2", ignored[0].parent_id)
        self.assertEqual("next", client._get_json.call_args_list[1].args[1]["cursor"])

    def test_link_header_next_relation_is_supported(self) -> None:
        link = (
            '<https://example.atlassian.net/wiki/api/v2/pages/1/direct-children?'
            'limit=250&cursor=next-page>; rel="next"; type="application/json", '
            '<https://example.atlassian.net/wiki/api/v2/pages/1/direct-children?'
            'limit=250&cursor=last-page>; rel="last"'
        )

        self.assertEqual(
            "https://example.atlassian.net/wiki/api/v2/pages/1/direct-children?"
            "limit=250&cursor=next-page",
            PGE.ConfluenceClient._next_link_from_header(link),
        )

    def test_live_client_rejects_foreign_and_downgrade_redirects(self) -> None:
        client = PGE.ConfluenceClient(
            "https://wiki.cloud.l-it.io",
            "validator@example.invalid",
            "secret-token",
        )
        request = PGE.Request(
            "https://wiki.cloud.l-it.io/wiki/api/v2/pages/1",
            headers={"Authorization": client.authorization},
        )
        handler = next(
            current
            for current in client.opener.handlers
            if isinstance(current, PGE.SameOriginRedirectHandler)
        )

        for redirect in (
            "https://attacker.example/collect",
            "http://wiki.cloud.l-it.io/collect",
        ):
            with self.subTest(redirect=redirect):
                with self.assertRaisesRegex(PGE.ConformanceError, "HTTPS origin"):
                    handler.redirect_request(
                        request,
                        None,
                        302,
                        "Found",
                        {},
                        redirect,
                    )

    def test_live_client_requires_an_exact_https_origin(self) -> None:
        for base_url in (
            "http://wiki.cloud.l-it.io",
            "https://wiki.cloud.l-it.io/wiki",
            "https://wiki.cloud.l-it.io?redirect=attacker.example",
            "https://user:token@wiki.cloud.l-it.io",
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(PGE.ConformanceError):
                    PGE.ConfluenceClient(base_url, "user@example.invalid", "token")
        with self.assertRaisesRegex(PGE.ConformanceError, "reviewed allowed origin"):
            PGE.ConfluenceClient(
                "https://attacker.example",
                "user@example.invalid",
                "token",
            )

    def test_config_cannot_redefine_the_compiled_reviewed_origin(self) -> None:
        payload = {
            "schema_version": 1,
            "allowed_confluence_origin": "https://attacker.example",
            "targets": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "targets.json"
            config.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PGE.ConformanceError, "reviewed origin"):
                PGE.read_config(config)

    def test_target_mapping_rejects_boolean_page_count(self) -> None:
        with self.assertRaisesRegex(PGE.ConformanceError, "expected_page_count"):
            PGE.target_from_mapping(
                {
                    "name": "test-target",
                    "root_page_id": "1",
                    "profile": "product",
                    "expected_page_count": True,
                }
            )


class SnapshotAndReportTests(unittest.TestCase):
    def test_inventory_digest_binds_title_and_storage_body_without_disclosing_them(self) -> None:
        original = page("1", "Sensitive Internal Title", product_metadata())
        changed = PGE.Page(
            page_id=original.page_id,
            title=original.title,
            parent_id=original.parent_id,
            body_storage=original.body_storage + "<p>changed</p>",
            status=original.status,
            version=original.version,
        )

        original_digest = PGE.tree_inventory_digest(PGE.Tree(target(), [original]))
        changed_digest = PGE.tree_inventory_digest(PGE.Tree(target(), [changed]))

        self.assertNotEqual(original_digest, changed_digest)
        self.assertNotIn("Sensitive Internal Title", original_digest)

    def test_exclusion_authority_versions_are_enforced_live_and_from_snapshot(self) -> None:
        current_target = target(
            expected_page_count=2,
            excluded_subtree_root_ids=("3",),
            exclusion_authorities=(PGE.ExclusionAuthority("1", 2),),
        )
        current_tree = PGE.Tree(
            target=current_target,
            pages=[page("1", "Authority", product_metadata())],
            excluded_pages=[
                PGE.ExcludedPage(
                    page_id="3",
                    title="Excluded",
                    parent_id="1",
                    status="current",
                    depth=1,
                    excluded_subtree_root_id="3",
                )
            ],
        )

        live_findings, _ = PGE.validate_tree(current_tree)
        self.assertIn(
            "tree.exclusion-authority-version",
            {finding.code for finding in live_findings},
        )

        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(
                json.dumps(PGE.snapshot_payload([current_tree], [])),
                encoding="utf-8",
            )
            snapshot_trees, _ = PGE.read_snapshot(snapshot)
        snapshot_findings, _ = PGE.validate_tree(snapshot_trees[0])
        self.assertIn(
            "tree.exclusion-authority-version",
            {finding.code for finding in snapshot_findings},
        )

    def test_missing_exclusion_authority_is_an_error(self) -> None:
        current_target = target(
            expected_page_count=2,
            excluded_subtree_root_ids=("3",),
            exclusion_authorities=(PGE.ExclusionAuthority("2", 1),),
        )
        current_tree = PGE.Tree(
            target=current_target,
            pages=[page("1", "Root", product_metadata())],
            excluded_pages=[
                PGE.ExcludedPage(
                    page_id="3",
                    title="Excluded",
                    parent_id="1",
                    status="current",
                    depth=1,
                    excluded_subtree_root_id="3",
                )
            ],
        )

        findings, _ = PGE.validate_tree(current_tree)

        self.assertIn(
            "tree.exclusion-authority-missing",
            {finding.code for finding in findings},
        )

    def test_snapshot_round_trip_and_redacted_report_never_include_body_or_title(self) -> None:
        current_tree = PGE.Tree(
            target=target(),
            pages=[page("1", "Sensitive Internal Title", product_metadata())],
        )
        payload = PGE.snapshot_payload([current_tree], [])
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps(payload), encoding="utf-8")
            trees, alignments = PGE.read_snapshot(snapshot)

        sensitive_finding = PGE.Finding(
            severity="error",
            code="content.sensitive-test",
            target="test-target",
            message="Sensitive finding detail must not leave the evidence store",
            page_id="1",
            page_title="Sensitive Internal Title",
        )
        report = PGE.build_report(trees, [sensitive_finding], redact_details=True)
        encoded = json.dumps(report)

        self.assertEqual([], alignments)
        self.assertNotIn("body_storage", encoded)
        self.assertNotIn("Sensitive Internal Title", encoded)
        self.assertNotIn("Sensitive finding detail", encoded)
        self.assertNotIn("sha256:", encoded)
        self.assertIsNone(report["findings"][0]["page_title"])

    def test_safe_write_refuses_existing_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_path = root / "target"
            target_path.write_text("unchanged", encoding="utf-8")
            link = root / "report.json"
            link.symlink_to(target_path)
            with self.assertRaisesRegex(PGE.ConformanceError, "symlink"):
                PGE.safe_write(link, "changed")
            self.assertEqual("unchanged", target_path.read_text(encoding="utf-8"))

    def test_safe_write_refuses_a_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)

            with self.assertRaisesRegex(PGE.ConformanceError, "symlink ancestor"):
                PGE.safe_write(alias / "nested" / "report.json", "sensitive")

            self.assertFalse((real / "nested").exists())


if __name__ == "__main__":
    unittest.main()
