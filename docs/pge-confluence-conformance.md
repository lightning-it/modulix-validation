# PGE Confluence Conformance

## Purpose

The PGE Confluence conformance harness produces repeatable, read-only evidence
for the documentation rules represented by PGE-DEC-036 and PGE-BLR-019. It
validates the accepted Product Decision set, the Template Library and Artifact
Catalog, and explicitly instantiated engagement documentation without changing
Confluence.

The checked-in target inventory is
[`inventories/pge/confluence-conformance.json`](../inventories/pge/confluence-conformance.json).
It is the review boundary for the allowed Confluence origin, page roots,
profiles, expected decision IDs, expected page counts, and governed subtree
exclusions and delegated coverage. The canonical PGE product target begins at
page `2875654145` and classifies every current descendant as directly
validated, delegated, or disposition-excluded. Its
excluded subtree roots are justified by the version-pinned Content State and
Disposition Manifest (`PGE-CONF-DISP-001`, page `2892759041`, Confluence
version 12, document version 2.1) and Item Level Content Disposition Register
(`PGE-CONF-DISP-001-R`, page `2892890133`, Confluence version 10, document
version 2.1). A live or offline run fails if
either authority page is absent from the included inventory or its Confluence
version differs. The reviewed full scan fixes the canonical inventory at 792
pages: 52 are validated directly under the product profile, 40 Product
Decision pages are delegated to `pge-product-decisions`, 11 Template Library
pages are delegated to `pge-template-library`, and 689 pages are below 69
explicit disposition roots. The 69 item-level roots may nest; each page is
assigned to its closest, most-specific configured root so the reported counts
remain disjoint. Completeness requires that exact total plus an explicit
classification for every returned page. Delegated page-ID inventories must
exactly match their separately crawled covering targets.

Traversal mode is also explicit. The Artifact Catalog is deliberately
`page-only`: its Template Library is audited as a separate recursive target,
avoiding a second validation of template placeholders under the product
profile. The `pge-product-baseline` workflow scope always selects the canonical
product and Product Decisions targets plus the coupled Template Library and
Artifact Catalog targets, so delegated coverage cannot be omitted. The Catalog
root remains directly validated in the canonical count and is also selected as
the alignment source; the report does not count that second validation inside
the 792-page canonical inventory. The LIT-PIS engagement target expects 389
page objects; its nine current embeds are non-page content and are reported,
not counted as pages. A
root, traversal mode, count, exclusion, or authority-version change therefore
requires the same pull request review as validator code.

## Validation Contract

Ordinary selected page trees are traversed recursively through the Confluence
Cloud REST API v2 direct-child relation. The canonical product target uses the
bounded descendants inventory so pages below non-page containers remain
visible. Pagination must finish without a repeated or missing cursor. Page and
non-page IDs must be unique, parent chains must trace to the selected root, and
every configured classified root must exist. Directly included page bodies are
validated under the canonical product profile. Delegated and excluded page
bodies are not fetched by that target; delegated bodies are fetched and
validated only by their named covering target, while excluded bodies are never
fetched. Non-page children such as folders, embeds, or whiteboards are not
treated as pages, but their type, identity, and parent are bound into the
evidence inventory digest.

The page-level rules require:

- exactly one H1 equal to the Confluence title for product and template pages,
  or to the readable content title without technical prefixes for engagement
  pages;
- `00 Inhaltsverzeichnis` as the exact first H2, associated with an expand
  macro that contains the native table-of-contents macro;
- contiguous two-level numbering for H2 and H3 headings;
- a horizontal rule as the final block of every H2 chapter;
- explicitly bold text in every table header, plus explicitly bold field names
  in `Field / Value` and `Feld / Wert` tables;
- complete, nonblank metadata with controlled lifecycle, classification,
  version, date, standard, and conformance values;
- no HTML comments, migration markers, or unresolved placeholders;
- placeholders only on pages explicitly identifiable as templates;
- the exact configured Accepted Product Decision set, inventoried from unique
  `Decision-ID` metadata rather than readable page titles, with no malformed,
  duplicate, missing, or unexpected IDs; an optional title ID must agree with
  metadata;
- the engagement root grammar `<Namespace>-<Content-Name>`, direct-child
  grammar `<Namespace>-<Scope>-<NN>-<Content-Name>`, and deeper-page grammar
  `<Namespace>-<Scope>-<Inherited-Codes>-<NN>-<Content-Name>`;
- exactly two ordering digits and three-character area codes derived from the
  parent content name: ignore `and`, `of`, and `the`; use the first initials of
  three or more words, the first initial plus the first two letters of the
  second word for two words, or the first three letters of one word; and
- bidirectional alignment of current Artifact Catalog and Template Library
  artifact types, without treating Proposed or Candidate records as baseline.

## Protected Live Workflow

The `PGE Confluence Conformance` workflow is dispatch-only and refuses every
revision except `main` in `lightning-it/modulix-validation-lit`. Its audit job uses
the protected `pge-confluence-read-only` GitHub Environment. Configure that
environment with required reviewers and a deployment rule limited to `main`.

Add one Environment Variable:

- `PGE_CONFLUENCE_BASE_URL`: exactly `https://wiki.cloud.l-it.io`, matching the
  checked-in allowed origin.

Add two Environment Secrets for a dedicated identity that can only view the
configured documentation roots:

- `PGE_CONFLUENCE_USER_EMAIL`;
- `PGE_CONFLUENCE_API_TOKEN`.

The client rejects any other origin and rejects redirects that change the HTTPS
origin, so the Basic credential cannot follow a cross-origin or downgrade
redirect. The secrets exist only in the single live-audit step. Checkout, unit
tests, summary publication, and artifact upload do not receive them. The
workflow has no arbitrary page-ID, URL, profile, or snapshot input. It uploads
only the detail-redacted JSON and Markdown reports; redacted findings omit page
titles as well as detailed messages. Snapshots and source bodies are never
uploaded.

The GitHub artifact is a transient transfer copy, not the authoritative
evidence record. Transfer the accepted report and its SHA-256 evidence digest
to the approved PGE evidence store, register the workflow run and Git commit,
and let the GitHub artifact expire after 14 days.

## Authorized Local Reproduction

The protected workflow is the preferred live path. An approved operator may
produce a local evidence copy with 1Password CLI or an equivalent
secret-injection process. The environment file must contain secret references,
not credential values, and must remain outside every Git worktree. Never paste,
type, or export the API token in an interactive shell, command argument,
terminal history, report, snapshot, or Git file.

```bash
op run --env-file=/approved/private/pge-confluence.env -- \
  python3 .github/scripts/pge-confluence-conformance.py \
  --config inventories/pge/confluence-conformance.json \
  --warnings-as-errors \
  --json-report /approved/evidence/pge-conformance-report.json \
  --markdown-report /approved/evidence/pge-conformance-report.md
```

The same command may add `--snapshot-out` only when the destination is an
approved evidence location. A snapshot contains complete Confluence page
bodies, inherits the highest source classification, and must never be committed
or uploaded as a normal workflow artifact.

An exact snapshot can be revalidated offline without credentials:

```bash
python3 .github/scripts/pge-confluence-conformance.py \
  --snapshot /approved/evidence/pge-confluence-snapshot.json \
  --warnings-as-errors \
  --json-report /approved/evidence/pge-conformance-rerun.json
```

## Acceptance and Recovery

A zero-error, zero-warning final run is necessary for documentation closure.
The report records total, directly validated, delegated, disposition-excluded,
and ignored counts; per-classified-root counts and covering target names; the
reviewed authority versions; and an inventory digest over the content
identities, parent relations, titles, revisions, and included storage bodies.
Only the aggregate digest is disclosed; individual title or body hashes are
not emitted. Target rows are independent scopes and are
not additive. A cross-target coverage section labels delegated coverage and
additional validation overlaps, including the Catalog's second validation.
The PGE Product Owner additionally
confirms the selected roots, fixed page counts, canonical classifications,
historical-content disposition, template/catalog alignment, and accepted
exceptions. The Evidence Register and LI-140 then reference the report digest,
workflow run, Git commit, reviewer, and acceptance decision.

The validator is read-only, so stopping a failed run requires no Confluence
rollback. If a report or snapshot is written to an unapproved location, stop
distribution and handle it as an information-classification incident. Do not
delete or weaken authoritative audit history to conceal the event.

## Local Quality Checks

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests/test_pge_confluence_conformance.py \
  tests/test_pge_confluence_workflow.py
python3 scripts/lit-repository-quality.py
actionlint .github/workflows/pge-confluence-conformance.yml
git diff --check
```
