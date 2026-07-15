#!/usr/bin/env python3
"""Evidence collector for the compliant-gcs primitive.

Queries live bucket configuration and emits a control-evidence JSON document
conforming to evidence.schema.json. Every record carries provenance: timestamp,
source command, collector version, target, and per-control expected vs observed.

Exit codes: 0 all controls satisfied, 2 collection failure,
3 (with --strict) one or more controls not satisfied.
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

COLLECTOR = {"name": "collect_evidence.py", "version": "1.0.0"}
SOURCE = "gcloud storage buckets describe --format=json"


def fetch(bucket):
    cmd = ["gcloud", "storage", "buckets", "describe", f"gs://{bucket}", "--format=json"]
    last = None
    for attempt in range(3):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
            return json.loads(out.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            last = e
            time.sleep(2**attempt)
    raise RuntimeError(f"collection failed after 3 attempts: {last}")


def get(observed, *paths):
    """First non-None value across candidate key paths (gcloud camelCase vs flat)."""
    for path in paths:
        node = observed
        ok = True
        for key in path.split("."):
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                ok = False
                break
        if ok and node is not None:
            return node
    return None


def assess(observed):
    labels = get(observed, "labels") or {}
    checks = [
        ("AC-3", "uniform bucket-level access", True,
         bool(get(observed, "uniform_bucket_level_access", "iamConfiguration.uniformBucketLevelAccess.enabled"))),
        ("AC-3", "public access prevention", "enforced",
         get(observed, "public_access_prevention", "iamConfiguration.publicAccessPrevention")),
        ("AU-11", "object versioning", True,
         bool(get(observed, "versioning_enabled", "versioning.enabled"))),
        ("AU-11", "retention policy present", True,
         get(observed, "retention_policy", "retentionPolicy") is not None),
        ("SC-12/SC-13/SC-28", "CMEK default key present", True,
         get(observed, "default_kms_key", "encryption.defaultKmsKeyName") is not None),
        ("CM-6", "required compliance labels", True,
         all(k in labels for k in ["project", "environment", "managed_by", "compliance_scope"])),
    ]
    controls = []
    for control_id, description, expected, observed_value in checks:
        controls.append({
            "control_id": control_id,
            "status": "satisfied" if observed_value == expected else "not-satisfied",
            "expected": expected,
            "observed": observed_value,
            "description": description,
        })
    return controls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--out", default="evidence/live")
    ap.add_argument("--strict", action="store_true", help="exit 3 if any control is not satisfied")
    args = ap.parse_args()

    try:
        observed = fetch(args.bucket)
    except RuntimeError as e:
        print(f"COLLECTION ERROR: {e}", file=sys.stderr)
        return 2

    doc = {
        "schema_version": "1.0",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collector": COLLECTOR,
        "source": SOURCE,
        "target": {"type": "gcs_bucket", "name": args.bucket},
        "controls": assess(observed),
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"{args.bucket}-{stamp}.json"
    out_path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out_path}")

    unsatisfied = [c for c in doc["controls"] if c["status"] != "satisfied"]
    if unsatisfied:
        for c in unsatisfied:
            print(f"NOT SATISFIED [{c['control_id']}] {c['description']}: observed {c['observed']!r}", file=sys.stderr)
        if args.strict:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
