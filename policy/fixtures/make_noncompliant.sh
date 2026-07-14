#!/usr/bin/env bash
# Generates the noncompliant test fixture by mutating the real (sanitized)
# compliant plan: turns off public access prevention and uniform access,
# strips versioning, and drops three of the four required labels.
# Expected denies when evaluated: AC-3 x2, AU-11 x1, CM-6 x3.
set -euo pipefail
cd "$(dirname "$0")/../.."
jq '(.resource_changes[] | select(.type=="google_storage_bucket").change.after) |=
      (.public_access_prevention = "inherited"
       | .uniform_bucket_level_access = false
       | .versioning = []
       | .labels = {"project": "cgep-lab"})' \
  policy/fixtures/compliant/gcs-plan.json \
  > policy/fixtures/noncompliant/gcs-plan.json
echo "wrote policy/fixtures/noncompliant/gcs-plan.json"
