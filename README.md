# GRC Engineering Capstone: one control set, four enforcement layers

This repository takes six NIST 800-53 rev 5 controls and refuses to let them
be just words in a policy document. Each one, SC-12, SC-13, SC-28, AC-3,
AU-11, and CM-6, is enforced at four independent layers: hardcoded into a
Terraform module so a compliant bucket is the only kind the module can build,
denied at merge time by an OPA/Rego gate that inspects every plan, watched at
runtime by a drift detector that catches settings changed after deployment,
and proven at audit time by an evidence collector and OSCAL component
definition that a machine can validate. One control set, four chances to catch
a violation, from the moment code is written to the moment an auditor asks for
proof.
             One control set (NIST 800-53 rev 5)
         SC-12  SC-13  SC-28  AC-3  AU-11  CM-6
                          |
    build            merge              runtime             audit
+------------+   +--------------+   +---------------+   +---------------+
| Terraform  |   | OPA / Rego   |   | drift         |   | evidence      |
| module     |-->| gate in CI   |-->| detector      |-->| collector +   |
| (hardcoded |   | (deny plans) |   | (alert on     |   | OSCAL comp-   |
|  floor)    |   |              |   |  live drift)  |   | def + schema  |
+------------+   +--------------+   +---------------+   +---------------+

## Scope

The end-to-end enforcement chain targets the compliant-gcs primitive on
Google Cloud. The compliant-s3 primitive (Lab 2.3) remains in the repository
as earlier portfolio work: it passes every static check in CI (fmt,
validate, tflint, checkov, semgrep) but intentionally sits outside the
policy, test, monitoring, and OSCAL chain. Depth on one chain demonstrates
the pattern; the pattern is cloud-portable.

## Repository map

| Path | What it is |
|---|---|
| terraform/primitives/compliant-gcs/ | The module: controls hardcoded at build time, plus terraform test suite |
| terraform/primitives/compliant-s3/ | Lab 2.3 primitive (static checks only, see Scope) |
| policy/ | Rego merge gate, unit tests, real-plan fixtures (compliant + scripted noncompliant) |
| monitoring/ | Runtime drift detector with dedup and alert routing, fixture-replay tests |
| evidence-automation/ | Evidence collector and the JSON Schema its output must satisfy |
| evidence/live/ | Collected, provenance-stamped evidence from the live bucket |
| oscal/ | OSCAL 1.1.2 component definition + vendored NIST schema |
| docs/ | Control-to-code matrix, state management rationale |
| .github/workflows/ | The staged compliance pipeline |
| scripts/run_all_checks.sh | Every deterministic check, in pipeline order, locally |

## Quickstart

Prerequisites: terraform >= 1.6, tflint, conftest, gitleaks, python3 with
`pip install -r requirements-ci.txt -r requirements-dev.txt`.
./scripts/run_all_checks.sh

## The gate blocks merges (receipt)

Branch protection on main requires every pipeline job. PR #REPLACE-WITH-PR-NUMBER
is an intentionally noncompliant change: the policy job fails and the merge
is blocked. It was closed unmerged and kept as the receipt.

## Policies worth knowing

State management: local state as a documented lab-scale choice, with the
migration path written down in docs/state-management.md. Raw state is never
committed, including as evidence (see the redaction note in
terraform/primitives/compliant-s3/evidence/lab-2-3/NOTE.md).

Evidence collection is a scripted manual step by design: granting a public
repository's CI standing cloud credentials is a worse security posture than
the automation gains. The production path would be GitHub OIDC to GCP
Workload Identity Federation, which needs no stored secrets.

Test fixtures are sanitized (example-project, no real identifiers); evidence
files keep real resource names on purpose, because evidence is provenance.

## License

MIT, see LICENSE.
