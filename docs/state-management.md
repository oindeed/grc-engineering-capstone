# State management

This repository intentionally uses local Terraform state for its lab-scale
primitives. Rationale: each consumer is a short-lived, single-operator lab
deployment with no team concurrency and no long-lived infrastructure, so a
remote backend adds operational surface without a locking or collaboration
benefit. State files are excluded from version control via .gitignore, and raw
state is never committed as evidence (see the evidence redaction note in
terraform/primitives/compliant-s3/evidence/lab-2-3/NOTE.md).

Migration path if this grew beyond lab scale: a GCS backend with versioning
and CMEK (the compliant-gcs module itself is the natural home for the state
bucket), enabled per consumer with a backend block and terraform init
-migrate-state.
