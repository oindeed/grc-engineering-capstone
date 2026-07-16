# Control-to-code matrix

Standard: NIST SP 800-53 rev 5. Scope: the compliant-gcs enforcement chain.
Every control below is enforced at four layers; every artifact below names
the controls it serves. The compliant-s3 primitive (Lab 2.3) remains in this
repository as earlier portfolio work and passes all static checks (fmt,
validate, tflint, checkov, semgrep), but sits outside the capstone
enforcement chain by scope; see the README scoping note.

## Control to artifacts

| Control | Requirement | Build (module) | Merge (policy) | Test | Runtime (detection) | Evidence | OSCAL |
|---|---|---|---|---|---|---|---|
| SC-12 | Key establishment, 90d rotation | compliant-gcs/main.tf google_kms_crypto_key | storage.rego [SC-12/SC-13/SC-28] | controls.tftest.hcl dev_baseline (rotation assert) | drift_detector SC-12/13/28 finding | evidence/live/*.json | component-definition sc-12 |
| SC-13 | Cryptographic protection (CMEK) | compliant-gcs/main.tf encryption block | storage.rego [SC-12/SC-13/SC-28] | tftest CMEK-adjacent asserts | drift_detector | evidence/live/*.json | sc-13 |
| SC-28 | Protection at rest | CMEK + prod retention floor | storage.rego [SC-28/AU-11] | tftest prod_short_retention_rejected | drift_detector | evidence/live/*.json | sc-28 |
| AC-3 | Access enforcement | uniform access + public access prevention | storage.rego [AC-3] x2 | tftest AC-3 asserts | drift_detector AC-3 findings | evidence/live/*.json | ac-3 |
| AU-11 | Audit record retention | versioning + retention_policy | storage.rego [AU-11] x2 | tftest AU-11 asserts | drift_detector AU-11 findings | evidence/live/*.json | au-11 |
| CM-6 | Configuration settings | required labels merged over consumer labels; env allow-list | storage.rego [CM-6] | tftest consumer_cannot_suppress_required_labels, unknown_environment_rejected | drift_detector CM-6 findings | evidence/live/*.json | cm-6 |

## Artifact to controls

| Path | Controls served |
|---|---|
| terraform/primitives/compliant-gcs/ | SC-12, SC-13, SC-28, AC-3, AU-11, CM-6 |
| terraform/primitives/compliant-s3/ | build-time hardening from Lab 2.3; outside the enforcement-chain scope (static checks only) |
| policy/gcs/storage.rego | AC-3, AU-11, SC-12, SC-13, SC-28, CM-6 |
| terraform/primitives/compliant-gcs/tests/controls.tftest.hcl | SC-12, SC-28, AC-3, AU-11, CM-6 |
| monitoring/drift_detector.py | AC-3, AU-11, SC-12/13/28, CM-6 |
| evidence-automation/collect_evidence.py | all of the above (evidence production) |
| oscal/component-definition.json | all of the above (machine-readable mapping) |
| .github/workflows/compliance.yml | enforcement of every layer on every change |

## Design rationale

### CMEK over Google-managed encryption (SC-12)

Google encrypts every bucket at rest by default, so the choice to bring a
customer-managed key was not about adding encryption where there was none. It
was about who holds the key. With a customer-managed KMS key, the ability to
decrypt lives in a resource I control and can audit, rotate, or revoke, rather
than being fully delegated to Google. I set a 90-day rotation so that the
window any single key version protects is bounded, which limits the blast
radius if a version is ever compromised. Ninety days is a defensible default
rather than a universal answer: some security teams will want a tighter
rotation to shrink that window further, others will accept a longer one to
reduce operational churn, and the value is meant to be tuned to an
organization's own risk tolerance and compliance obligations. The tradeoff I
accepted is that I now own the key's lifecycle, and destroying it carelessly
would orphan the data it protects. I took on that operational weight because
for a control meant to demonstrate key establishment and management, delegating
the key entirely to the provider would have defeated the point.

### Deny-by-default policy

The policy gate is written to deny rather than to permit. Each rule describes a
specific way a bucket can be wrong, an unencrypted plan, public access left
reachable, versioning off, a missing label, and anything that trips a rule is
blocked from merging. I chose this direction deliberately. An allow-list, where
only pre-approved configurations pass, sounds safer but fails quietly the
moment someone introduces a valid-but-unforeseen shape the list never
anticipated, and it tends to grow into an unmaintainable catalog of exceptions.
Deny-by-default inverts the burden: the safe path is the default, and only the
known-bad patterns need to be enumerated and justified. The one place I do use
an explicit allow-list is the environment variable, which accepts only a small
closed set of values, because an unrecognized value there almost certainly
signals a mistake rather than a new legitimate case. The distinction is the
point: allow-list where the valid set is small and closed, deny-by-default
where it is open-ended.

### Two enforcement points for one rule (prod retention floor)

The rule that production buckets must retain data for at least 365 days lives
in two places: the module's own variable validation, and the Rego policy gate.
That looks redundant until you notice the two are protecting against different
failures. The module validation protects the person using the module. If
someone sets a prod environment with a 30-day retention, the module refuses to
plan, and they get an immediate, local error before anything reaches review.
But the module can only protect code that actually calls the module. The policy
gate protects the organization from the plan that never used the module at all,
the hand-rolled bucket, the copied-and-modified resource, the shortcut taken
under deadline. That plan sails past the module's validation because it never
touched it, and the gate is the only thing standing in its way at merge time.
Same rule, two trust boundaries: one assumes you are inside the module and
trying to do the right thing, the other assumes nothing and inspects the plan
on its way in.

### Scoping to one cloud chain

An earlier version of this work would have mirrored the whole enforcement chain
across both GCS and S3. I cut that on purpose. The point of the capstone is to
demonstrate that a single control set can be enforced at four layers, build,
merge, runtime, and audit, and that argument is made just as convincingly on
one cloud as on two. Building it twice would have doubled the surface area
while adding no new idea, and worse, it would have pulled time away from making
any single chain deep and correct into making two chains shallow. So the GCS
chain is complete end to end, and the S3 primitive stays in the repo as earlier
portfolio work that still passes every static check, honestly labeled as out of
the enforcement scope. The pattern itself is cloud-portable: the Rego rules,
the drift detector, the evidence collector, and the OSCAL mapping are all
structured the same way regardless of provider, so extending to S3 later is a
matter of repetition, not redesign. Depth over breadth was the call, and
scoping it out loud is part of the engineering, not a gap in it.

### Local state as a documented choice

This repository uses local Terraform state rather than a remote backend, and
that is a deliberate lab-scale decision, not an oversight. Remote state earns
its keep when a team shares infrastructure: it provides locking so two people
cannot apply at once, and a shared source of truth so nobody drifts. Neither
condition holds here. These are short-lived, single-operator lab deployments
with no concurrency to guard against, so a remote backend would add operational
machinery and another cloud dependency without buying any of the safety it
exists to provide. What does matter at any scale is that state never leaks, so
state files are gitignored and raw state is never committed as evidence, with a
redaction note left where one used to sit. If this grew into shared, long-lived
infrastructure, the migration path is written down: a versioned,
CMEK-encrypted GCS backend, which the compliant-gcs module itself is well
suited to provision. The choice is scoped to the situation, and the moment the
situation changes, the documented next step changes with it.
