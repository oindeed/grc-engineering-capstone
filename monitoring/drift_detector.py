#!/usr/bin/env python3
"""Runtime drift detector for the compliant-gcs primitive.

Queries live GCS bucket configuration and compares it against the committed
control baseline (monitoring/baseline.json). Each finding is tagged with the
NIST 800-53 rev 5 control it violates. Findings are deduplicated by
fingerprinting the finding set; alerts route per monitoring/config.json.

Exit codes: 0 no drift, 1 drift detected (alert emitted), 2 collection error.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_json(path):
    with open(path) as f:
        return json.load(f)


def fetch_bucket_config(bucket):
    """Query live bucket state via gcloud. Retries transient failures.

    Kept as a standalone function so tests can replace it with fixture data
    (replay-against-fixtures).
    """
    cmd = ["gcloud", "storage", "buckets", "describe", f"gs://{bucket}", "--format=json"]
    last_err = None
    for attempt in range(3):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
            return json.loads(out.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            last_err = e
            time.sleep(2**attempt)
    raise RuntimeError(f"collection failed after 3 attempts: {last_err}")


def evaluate(observed, baseline):
    """Compare observed bucket config to the control baseline.

    Returns a list of findings; empty list means no drift.
    """
    findings = []
    b = baseline["controls"]

    def finding(control_id, field, expected, actual):
        findings.append({
            "control_id": control_id,
            "field": field,
            "expected": expected,
            "observed": actual,
        })

    ubla = observed.get("uniform_bucket_level_access", observed.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled"))
    if bool(ubla) is not b["AC-3.uniform_bucket_level_access"]:
        finding("AC-3", "uniform_bucket_level_access", True, ubla)

    pap = observed.get("public_access_prevention", observed.get("iamConfiguration", {}).get("publicAccessPrevention"))
    if pap != b["AC-3.public_access_prevention"]:
        finding("AC-3", "public_access_prevention", "enforced", pap)

    versioning = observed.get("versioning_enabled", observed.get("versioning", {}).get("enabled", False))
    if bool(versioning) is not b["AU-11.versioning_enabled"]:
        finding("AU-11", "versioning_enabled", True, versioning)

    retention = observed.get("retention_policy", observed.get("retentionPolicy"))
    if b["AU-11.retention_present"] and not retention:
        finding("AU-11", "retention_policy", "present", None)

    kms = observed.get("default_kms_key", observed.get("encryption", {}).get("defaultKmsKeyName"))
    if b["SC-12_13_28.cmek_key_present"] and not kms:
        finding("SC-12/SC-13/SC-28", "default_kms_key", "present", None)

    labels = observed.get("labels", {}) or {}
    for required in b["CM-6.required_labels"]:
        if required not in labels:
            finding("CM-6", f"labels.{required}", "present", None)

    return findings


def fingerprint(findings):
    canon = json.dumps(sorted(findings, key=lambda f: (f["control_id"], f["field"])), sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()


def should_alert(findings, config, state_path):
    """Dedup and thresholding: alert on a new finding-set fingerprint once it
    has been seen on `consecutive_required` consecutive runs."""
    fp = fingerprint(findings)
    state = {"fingerprint": None, "count": 0, "alerted": False}
    if state_path.exists():
        state = json.loads(state_path.read_text())
    if state.get("fingerprint") == fp:
        state["count"] += 1
    else:
        state = {"fingerprint": fp, "count": 1, "alerted": False}
    fire = state["count"] >= config["consecutive_required"] and not state["alerted"]
    if fire:
        state["alerted"] = True
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state))
    return fire


def route_alert(findings, bucket, config):
    payload = {
        "alert": "control_drift",
        "target": f"gs://{bucket}",
        "owner": config["owner"],
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    if config["route"] == "webhook":
        url = os.environ.get(config["webhook_url_env"], "")
        if not url:
            print(f"ALERT ROUTING ERROR: {config['webhook_url_env']} not set; falling back to log", file=sys.stderr)
        elif not url.lower().startswith("https://"):
            # Reject non-HTTPS schemes (e.g. file://) so a misconfigured webhook
            # URL cannot be coerced into reading local files or plaintext egress.
            print(f"ALERT ROUTING ERROR: {config['webhook_url_env']} must be https://; falling back to log", file=sys.stderr)
        else:
            req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
            # URL is operator-supplied via env var and validated above to be https:// only.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            urllib.request.urlopen(req, timeout=10)
            return
    print("DRIFT ALERT " + json.dumps(payload), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--baseline", default=str(HERE / "baseline.json"))
    ap.add_argument("--config", default=str(HERE / "config.json"))
    args = ap.parse_args()

    config = load_json(args.config)
    baseline = load_json(args.baseline)

    try:
        observed = fetch_bucket_config(args.bucket)
    except RuntimeError as e:
        print(f"COLLECTION ERROR: {e}", file=sys.stderr)
        return 2

    findings = evaluate(observed, baseline)
    if not findings:
        print(f"no drift: gs://{args.bucket} matches control baseline")
        return 0

    state_path = Path(config["state_dir"]) / f"{args.bucket}.json"
    if should_alert(findings, config, state_path):
        route_alert(findings, args.bucket, config)
    else:
        print(f"drift present but deduplicated (already alerted): {len(findings)} finding(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
