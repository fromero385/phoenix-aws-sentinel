"""
Tests for Phoenix AWS Sentinel Standalone CLI & Detection Engine.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_standalone_demo_execution():
    """Verify built-in demo executes with zero credentials and returns 0."""
    script = ROOT_DIR / "sentinel.py"
    res = subprocess.run(
        [sys.executable, str(script), "--demo", "--format", "json"],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0, f"Error: {res.stderr}"
    data = json.loads(res.stdout)
    assert data["mode"] == "SYNTHETIC_DEMO"
    assert data["total_findings"] >= 4
    assert data["estimated_monthly_bleed_usd"] > 0
    assert data["verified_realized_savings_usd"] == 0.0


def test_iam_policy_contains_no_write_actions():
    """Verify that iam-policy.json contains strictly read-only permissions."""
    policy_path = ROOT_DIR / "iam-policy.json"
    with open(policy_path, "r", encoding="utf-8") as fh:
        policy = json.load(fh)

    for stmt in policy.get("Statement", []):
        for action in stmt.get("Action", []):
            name = action.split(":")[-1]
            assert name.startswith("Describe") or name.startswith("Get") or name.startswith("List")
            for forbidden in ["Create", "Delete", "Modify", "Put", "Update"]:
                assert forbidden.lower() not in name.lower()


if __name__ == "__main__":
    test_standalone_demo_execution()
    test_iam_policy_contains_no_write_actions()
    print("ALL STANDALONE TESTS PASSED SUCCESSFULLY.")

