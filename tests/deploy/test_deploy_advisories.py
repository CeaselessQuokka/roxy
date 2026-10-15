"""The dependency audit at deploy: advisories.json for health check H-VERSION (plan 13.2, 17.4 step 9).

What this is
    Runs the real deploy/deploy.sh in the sandbox server and checks the record it writes in
    /var/lib/roxy-deploy/advisories.json: CI's pip-audit counts and ids when the workflow passes them
    (ROXY_ADVISORY_COUNT, ROXY_ADVISORY_FIXABLE, ROXY_ADVISORY_IDS), an honest "not recorded" for a deploy started by
    hand or with a value that is not a count, the record a rollback puts back, a failed deploy leaving the previous
    record alone, and that the health check's own reader understands every form.

Why it exists
    H-VERSION says "dependencies have no known vulnerabilities (from the last CI audit recorded at deploy)". The
    deploy is the only step that knows which commit went live, and the workflow is the only place the audit result
    exists, so the deploy must write what CI found for exactly that commit, and must never invent a zero.

How it works
    `DeploySandbox` (tests/deploy/deploy_sandbox.py) runs deploy.sh against stub systemctl, sudo, curl and uv, with
    the deploy state directory inside the test's temporary directory. The record is read back with json and with
    `roxy.health.facts.advisories_from`, the parser H-VERSION uses.

What to read next
    deploy/deploy.sh (`advisories_json`, `record_advisories`), src/roxy/health/facts.py (`ADVISORY_FILES`),
    .github/workflows/ci.yml (job `dependency-audit`) and .github/workflows/deploy.yml.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
import yaml
from deploy_sandbox import DEPLOY, REPO, DeploySandbox

from roxy.health.facts import ADVISORY_FILES, advisories_from

pytestmark = [pytest.mark.deploy]


def deploy(box: DeploySandbox, marker: str, **env: str) -> str:
    sha = box.make_commit(marker)
    result = box.run(sha, **env)
    assert result.returncode == 0, result.stdout + result.stderr
    return sha


def record(box: DeploySandbox) -> dict[str, object]:
    return dict(json.loads((box.deploy_state / "advisories.json").read_text()))


def test_deploy_records_the_ci_audit(sandbox: DeploySandbox) -> None:
    sha = sandbox.make_commit("AUDITED")
    result = sandbox.run(
        sha, ROXY_ADVISORY_COUNT="2", ROXY_ADVISORY_FIXABLE="0", ROXY_ADVISORY_IDS="PYSEC-2026-1,GHSA-abcd-efgh-ijkl"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Dependency audit recorded: 2 known advisories (ci)." in result.stdout
    found = record(sandbox)
    assert found["count"] == 2
    assert found["fixable"] == 0
    assert found["ids"] == ["PYSEC-2026-1", "GHSA-abcd-efgh-ijkl"]
    assert found["source"] == "ci"
    assert found["commit"] == sha
    assert advisories_from(found) == 2, "what H-VERSION reads"
    path = sandbox.deploy_state / "advisories.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o644, "readable by the roxy user"
    assert json.loads((sandbox.releases / sha / ".roxy-advisories.json").read_text()) == found


def test_a_clean_audit_is_zero_not_missing(sandbox: DeploySandbox) -> None:
    deploy(sandbox, "CLEAN", ROXY_ADVISORY_COUNT="0", ROXY_ADVISORY_FIXABLE="0")
    found = record(sandbox)
    assert (found["count"], found["ids"], found["source"]) == (0, [], "ci")
    assert advisories_from(found) == 0


def test_a_deploy_by_hand_is_not_recorded_never_zero(sandbox: DeploySandbox) -> None:
    sha = sandbox.make_commit("BY_HAND")
    result = sandbox.run(sha)
    assert result.returncode == 0, result.stderr
    found = record(sandbox)
    assert found["count"] is None
    assert found["source"] == "not_recorded"
    assert found["commit"] == sha
    assert advisories_from(found) is None, "H-VERSION shows 'advisories not recorded'"
    assert "Dependency audit not recorded" in result.stdout
    assert not (sandbox.releases / sha / ".roxy-advisories.json").exists()


@pytest.mark.parametrize("count", ["2; touch /tmp/pwned", "-1", "1e9", "two", "9999999"])
def test_a_value_that_is_not_a_count_is_not_recorded(sandbox: DeploySandbox, count: str) -> None:
    deploy(sandbox, "ODD", ROXY_ADVISORY_COUNT=count, ROXY_ADVISORY_IDS="GHSA-1;rm -rf /,PYSEC-2026-2")
    found = record(sandbox)
    assert found["count"] is None
    assert found["source"] == "not_recorded"
    assert found["ids"] == []


def test_advisory_ids_are_filtered_and_bounded(sandbox: DeploySandbox) -> None:
    ids = ",".join(["GHSA-ok-1", "$(id)", "PYSEC 2026", "../x", *[f"CVE-2026-{n}" for n in range(60)]])
    deploy(sandbox, "IDS", ROXY_ADVISORY_COUNT="61", ROXY_ADVISORY_IDS=ids)
    found = record(sandbox)
    found_ids = found["ids"]
    assert isinstance(found_ids, list)
    assert found_ids[0] == "GHSA-ok-1"
    assert "$(id)" not in found_ids
    assert "PYSEC 2026" not in found_ids
    assert len(found_ids) == 50


def test_rollback_puts_back_the_record_of_its_release(sandbox: DeploySandbox) -> None:
    first = deploy(sandbox, "A", ROXY_ADVISORY_COUNT="1", ROXY_ADVISORY_IDS="PYSEC-2026-1")
    deploy(sandbox, "B", ROXY_ADVISORY_COUNT="3")
    assert record(sandbox)["count"] == 3
    result = sandbox.run(script=sandbox.opt / "deploy_rollback.sh")
    assert result.returncode == 0, result.stdout + result.stderr
    found = record(sandbox)
    assert found["commit"] == first
    assert found["count"] == 1
    assert found["ids"] == ["PYSEC-2026-1"]
    assert found["restored_by"] == "rollback"


def test_rollback_to_a_release_without_a_record_is_not_recorded(sandbox: DeploySandbox) -> None:
    first = deploy(sandbox, "A")
    deploy(sandbox, "B", ROXY_ADVISORY_COUNT="0")
    result = sandbox.run(script=sandbox.opt / "deploy_rollback.sh")
    assert result.returncode == 0, result.stderr
    found = record(sandbox)
    assert (found["commit"], found["count"], found["source"]) == (first, None, "not_recorded")


def test_a_failed_deploy_leaves_the_live_record(sandbox: DeploySandbox) -> None:
    first = deploy(sandbox, "LIVE", ROXY_ADVISORY_COUNT="1")
    sandbox.flag("unhealthy-green")
    result = sandbox.run(sandbox.make_commit("SICK"), ROXY_ADVISORY_COUNT="5")
    assert result.returncode != 0
    found = record(sandbox)
    assert (found["commit"], found["count"]) == (first, 1)


def test_the_record_is_where_the_health_check_reads_it() -> None:
    text = (DEPLOY / "deploy.sh").read_text()
    assert 'DEPLOY_STATE_DIR="${ROXY_DEPLOY_STATE_DIR:-/var/lib/roxy-deploy}"' in text
    assert 'write_file "$DEPLOY_STATE_DIR/advisories.json"' in text
    assert ADVISORY_FILES[0] == Path("/var/lib/roxy-deploy/advisories.json")
    # Written before deployed_version: roxy-audit.path fires on that file, and H-VERSION reads both together.
    assert text.index("record_advisories ||") < text.index('write_file "$DEPLOY_STATE_DIR/deployed_version"')


def test_the_workflow_hands_the_audit_to_deploy_sh() -> None:
    deploy_yml = yaml.safe_load((REPO / ".github" / "workflows" / "deploy.yml").read_text())
    job = deploy_yml["jobs"]["deploy"]
    assert job["if"] is False, "deploy.yml ships disabled until the cutover (plan 17.4)"
    step = job["steps"][0]
    env = step["env"]
    assert env["ROXY_ADVISORY_COUNT"] == "${{ needs.ci.outputs.advisories }}"
    assert env["ROXY_ADVISORY_FIXABLE"] == "${{ needs.ci.outputs.advisories_fixable }}"
    assert env["ROXY_ADVISORY_IDS"] == "${{ needs.ci.outputs.advisory_ids }}"
    for name in ("ROXY_ADVISORY_COUNT", "ROXY_ADVISORY_FIXABLE", "ROXY_ADVISORY_IDS"):
        assert name in step["with"]["envs"].split(",")
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    outputs = ci[True]["workflow_call"]["outputs"]  # PyYAML reads the key `on` as True
    assert outputs["advisories"]["value"] == "${{ jobs.dependency-audit.outputs.advisories }}"
    assert outputs["advisories_fixable"]["value"] == "${{ jobs.dependency-audit.outputs.fixable }}"
    assert outputs["advisory_ids"]["value"] == "${{ jobs.dependency-audit.outputs.ids }}"
    audit = ci["jobs"]["dependency-audit"]
    assert set(audit["outputs"]) == {"advisories", "fixable", "ids"}
