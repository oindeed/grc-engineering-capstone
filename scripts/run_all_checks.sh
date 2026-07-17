#!/usr/bin/env bash
# Runs every deterministic check in this repository, in pipeline order.
# A clean exit here predicts a clean CI run.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== fmt =="
terraform fmt -check -recursive terraform/

echo "== tflint =="
tflint --init >/dev/null
tflint --recursive --config "$(pwd)/.tflint.hcl"

echo "== validate =="
for d in terraform/primitives/compliant-gcs terraform/primitives/compliant-gcs/consumers/dev terraform/primitives/compliant-gcs/consumers/prod terraform/primitives/compliant-s3; do
  terraform -chdir="$d" init -backend=false -input=false >/dev/null
  terraform -chdir="$d" validate
done

echo "== checkov =="
checkov -d terraform --quiet --compact

echo "== semgrep =="
semgrep scan --config auto --error

echo "== gitleaks =="
gitleaks detect --source .

echo "== policy: rego unit tests =="
conftest verify -p policy

echo "== policy: compliant fixtures pass =="
conftest test --all-namespaces -p policy policy/fixtures/compliant/

echo "== policy: noncompliant fixture is denied =="
if conftest test --all-namespaces -p policy policy/fixtures/noncompliant/ >/dev/null 2>&1; then
  echo "ERROR: noncompliant fixture passed the gate"; exit 1
fi
echo "denied as expected"

echo "== terraform test =="
terraform -chdir=terraform/primitives/compliant-gcs test

echo "== pytest =="
pytest monitoring/tests evidence-automation/tests -q

echo "== machine-readable docs =="
check-jsonschema --schemafile oscal/schema/oscal_component_schema.json oscal/component-definition.json
check-jsonschema --schemafile evidence-automation/evidence.schema.json evidence/live/*.json

echo ""
echo "ALL CHECKS PASSED"
