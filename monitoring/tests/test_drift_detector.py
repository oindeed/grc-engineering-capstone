"""Replay-against-fixtures tests for the drift detector.

Each test name carries the control under test so a failure names the
compliance gap it indicates.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import drift_detector as dd

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
BASELINE = json.loads((Path(__file__).resolve().parents[1] / "baseline.json").read_text())


def load(name):
    return json.loads((FIXTURES / name).read_text())


def test_compliant_bucket_produces_no_findings():
    assert dd.evaluate(load("compliant.json"), BASELINE) == []


def test_ac3_public_access_drift_detected():
    findings = dd.evaluate(load("drift_public_access.json"), BASELINE)
    controls = {f["control_id"] for f in findings}
    assert "AC-3" in controls
    assert len([f for f in findings if f["control_id"] == "AC-3"]) == 2


def test_dedup_suppresses_repeat_alerts(tmp_path):
    findings = dd.evaluate(load("drift_public_access.json"), BASELINE)
    config = {"consecutive_required": 1, "owner": "test", "route": "log", "webhook_url_env": "X", "state_dir": str(tmp_path)}
    state = tmp_path / "bucket.json"
    assert dd.should_alert(findings, config, state) is True
    assert dd.should_alert(findings, config, state) is False


def test_changed_findings_realert(tmp_path):
    config = {"consecutive_required": 1, "owner": "test", "route": "log", "webhook_url_env": "X", "state_dir": str(tmp_path)}
    state = tmp_path / "bucket.json"
    first = dd.evaluate(load("drift_public_access.json"), BASELINE)
    assert dd.should_alert(first, config, state) is True
    obs = load("drift_public_access.json")
    obs["versioning_enabled"] = False
    second = dd.evaluate(obs, BASELINE)
    assert dd.should_alert(second, config, state) is True
