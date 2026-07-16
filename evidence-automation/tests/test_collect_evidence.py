"""Tests for the evidence collector: control assessment and provenance shape.
Live collection is exercised via fixture replay (fetch is not called)."""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_evidence as ce

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / "monitoring" / "fixtures" / "compliant.json").read_text())


def test_compliant_bucket_all_controls_satisfied():
    controls = ce.assess(FIXTURE)
    assert len(controls) == 6
    assert all(c["status"] == "satisfied" for c in controls)


def test_ac3_public_access_not_satisfied():
    obs = dict(FIXTURE, public_access_prevention="inherited")
    controls = ce.assess(obs)
    ac3 = [c for c in controls if c["control_id"] == "AC-3" and "public" in c["description"]]
    assert ac3[0]["status"] == "not-satisfied"
    assert ac3[0]["observed"] == "inherited"


def test_control_ids_match_evidence_schema_pattern():
    pattern = re.compile(r"^[A-Z]{2}-[0-9]+(/[A-Z]{2}-[0-9]+)*$")
    for c in ce.assess(FIXTURE):
        assert pattern.match(c["control_id"]), c["control_id"]
