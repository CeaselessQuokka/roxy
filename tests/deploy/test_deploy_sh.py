"""deploy.sh in a sandbox: every v1 deploy_test.sh scenario and every plan 19.9 scenario (plan 17.4, 19.9).

What this is
    Each test builds a fake server (`DeploySandbox` in conftest.py), commits a minimal Roxy tree to a local "GitHub"
    repository, runs the real deploy/deploy.sh (or deploy_rollback.sh) and checks what happened: which color runs
    which release, where nginx points, what was recorded, and what the stubs were asked to do.

Why it exists
    The deploy is the one program that can take the site down, and its failure paths are the ones nobody runs by
    hand. v1's tests/deploy_test.sh had 9 scenarios (46 checks); its missing cases (a service that never comes up,
    a concurrent deploy, the workflow bootstrap) were exactly where v1 broke. The test names map to v1 scenarios
    (v1_1 ... v1_9) and to the plan 19.9 list, so tests/V1_PARITY.md can point at them.

How it works
    Scenario flags make a stub fail on purpose (`fail-uv-sync`, `fail-migrate`, `unhealthy-green`, ...). After a
    failure every test asserts the rollback contract: exit status non-zero, the old color still running and still
    selected by nginx, the idle color stopped, and a failure record for the alert unit.

What to read next
    `tests/deploy/conftest.py` (the sandbox and stubs), then `deploy/deploy.sh`.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from deploy_sandbox import REPO, DeploySandbox

pytestmark = [pytest.mark.deploy]


def deployed(box: DeploySandbox, marker: str = "VERSION_ONE") -> str:
    """Commit and deploy one release successfully; returns its sha."""
    sha = box.make_commit(marker)
    result = box.run(sha)
    assert result.returncode == 0, result.stdout + result.stderr
    return sha


def assert_rolled_back(box: DeploySandbox, result: subprocess.CompletedProcess[str], *, old: str, old_sha: str) -> None:
    """The rollback contract after a failed deploy (plan 17.4 on_error)."""
    assert result.returncode != 0, result.stdout
    assert box.active_color() == old, "nginx must still point at the old color"
    assert box.running(old), "the old color must keep running"
    assert box.unit_value(old, "release") == old_sha
    idle = "green" if old == "blue" else "blue"
    assert not box.running(idle), "the idle color must be stopped"
    assert "Previous build restored. The site should be back up; nothing was upgraded." in result.stderr
    record = json.loads((box.deploy_state / "last_failure.json").read_text())
    assert record["status"] == "failed"


# ------------------------------------------------------------------------------------- clean deploys


def test_v1_1_clean_deploy(sandbox: DeploySandbox) -> None:
    """v1 scenario 1 and plan 19.9 "clean deploy": blue then green, switch, old color stopped, records written."""
    first = deployed(sandbox, "VERSION_ZERO")
    assert sandbox.active_color() == "blue"
    sha = sandbox.make_commit("VERSION_ONE")
    sandbox.clear_calls()
    result = sandbox.run(sha)
    assert result.returncode == 0, result.stdout + result.stderr
    assert sandbox.active_color() == "green"
    assert sandbox.running("green")
    assert not sandbox.running("blue")
    assert sandbox.unit_value("green", "release") == sha
    assert sandbox.current("green") == sha
    assert sandbox.current("blue") == first
    release = sandbox.releases / sha
    assert (release / ".roxy-release-complete").read_text().strip() == sha
    assert 'MARKER = "VERSION_ONE"' in (release / "src" / "roxy" / "__init__.py").read_text()
    assert (release / ".venv" / "bin" / "python").exists()
    assert (release / "build" / "public" / "static-manifest.json").exists()
    assert (sandbox.deploy_state / "deployed_version").read_text().strip() == sha
    record = json.loads((sandbox.deploy_state / "last_deploy.json").read_text())
    assert record["status"] == "succeeded"
    assert record["sha"] == sha
    assert not (sandbox.deploy_state / "last_failure.json").exists()
    assert (sandbox.opt / "deploy.sh").exists()
    assert not list(sandbox.releases.glob("*.new"))
    assert not list(sandbox.releases.glob(".*"))
    for line in (
        "==> Build verified.",
        "Step 5: health gate on green",
        "Step 6: switching nginx to green",
        "Site successfully deployed.",
        "==> Done.",
    ):
        assert line in result.stdout
    calls = sandbox.calls()
    restart = calls.index("systemctl restart roxy@green.service")
    switch = calls.index("roxy-switch-color green")
    stop = calls.index("systemctl stop roxy@blue.service")
    assert restart < switch < stop, "start idle, then switch, then stop old"
    assert any("smoke_remote.py --color green" in call for call in calls)
    assert any(call.startswith("uv sync") and "--frozen" in call for call in calls)


def test_release_ships_compiled_bytecode(sandbox: DeploySandbox) -> None:
    """The release is read-only to the service, so Python can never cache bytecode there itself: the build compiles
    it once, or every worker start and max_requests recycle would compile the whole app from source."""
    deployed(sandbox)
    syncs = [call for call in sandbox.calls() if call.startswith("uv sync")]
    assert syncs
    assert all("--compile-bytecode" in call for call in syncs), syncs


def test_clean_deploy_releases_are_readable_by_the_service(sandbox: DeploySandbox) -> None:
    """The roxy user reads the release: no group or world write, everything world readable (umask 0022)."""
    sha = deployed(sandbox)
    for path in (sandbox.releases / sha).rglob("*"):
        if path.is_symlink():
            continue
        mode = path.stat().st_mode & 0o777
        assert mode & 0o022 == 0, f"{path} is group or world writable"
        assert mode & 0o004, f"{path} is not world readable"


def test_v1_2_script_updates_itself_after_success(sandbox: DeploySandbox) -> None:
    """v1 scenario 2: the release's deploy.sh replaces /opt/roxy/deploy.sh, but only after a successful deploy."""
    deployed(sandbox, "VERSION_ONE")
    sha = sandbox.make_commit("VERSION_TWO", deploy_sh_extra="\n# NEWER VERSION MARKER\n")
    result = sandbox.run(sha)
    assert result.returncode == 0, result.stderr
    assert "# NEWER VERSION MARKER" in (sandbox.opt / "deploy.sh").read_text()
    assert not list(sandbox.opt.glob(".deploy.sh.new"))


def test_self_update_is_skipped_when_the_deploy_fails(sandbox: DeploySandbox) -> None:
    deployed(sandbox, "VERSION_ONE")
    sha = sandbox.make_commit("VERSION_TWO", deploy_sh_extra="\n# NEWER VERSION MARKER\n")
    sandbox.flag("smoke-fail")
    result = sandbox.run(sha)
    assert result.returncode != 0
    assert "# NEWER VERSION MARKER" not in (sandbox.opt / "deploy.sh").read_text()


def test_v1_7_redeploy_of_a_built_release_reuses_it(sandbox: DeploySandbox) -> None:
    """v1 scenario 7: unchanged dependencies are not rebuilt (here: the same release is never built twice)."""
    first = deployed(sandbox, "VERSION_A")
    second = deployed(sandbox, "VERSION_B")
    sandbox.clear_calls()
    result = sandbox.run(first)  # back to A: its release is still built
    assert result.returncode == 0, result.stderr
    assert "Dependencies unchanged; keeping the existing environment." in result.stdout
    assert not any(call.startswith("uv sync") for call in sandbox.calls())
    assert sandbox.unit_value(sandbox.active_color() or "", "release") == first
    sandbox.clear_calls()
    third = sandbox.make_commit("VERSION_C", lock_extra="flask==3.1.2")
    result = sandbox.run(third)
    assert result.returncode == 0, result.stderr
    assert "Dependencies changed (or no usable environment); rebuilding." in result.stdout
    assert any(call.startswith("uv sync") for call in sandbox.calls())
    assert second != third


def test_v1_9_first_ever_deploy_on_a_bare_server(sandbox: DeploySandbox) -> None:
    """v1 scenario 9 and plan 19.9 "first-ever deploy": no releases, no active color, nothing running."""
    sha = sandbox.make_commit("VERSION_FIRST")
    result = sandbox.run(sha)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "first deploy" in result.stdout
    assert sandbox.active_color() == "blue"
    assert sandbox.running("blue")
    assert f"roxy-nginx-apply {sha} --initial-color blue" in sandbox.calls()
    assert "systemctl stop" not in "\n".join(sandbox.calls())
    assert (sandbox.deploy_state / "deployed_version").read_text().strip() == sha


def test_v1_6_runs_when_started_with_sh(sandbox: DeploySandbox) -> None:
    """v1 scenario 6: `sh deploy.sh` re-executes itself under bash (dash knows no pipefail)."""
    sha = sandbox.make_commit("VERSION_SH")
    result = sandbox.run(sha, shell="sh")
    assert result.returncode == 0, result.stderr
    assert "Illegal option" not in result.stderr
    assert sandbox.unit_value("blue", "release") == sha


def test_nginx_config_is_applied_only_when_it_changed(sandbox: DeploySandbox) -> None:
    first = deployed(sandbox, "ONE")
    assert sandbox.calls().count(f"roxy-nginx-apply {first} --initial-color blue") == 1
    sandbox.clear_calls()
    second = deployed(sandbox, "TWO")
    assert not any(call.startswith("roxy-nginx-apply") for call in sandbox.calls()), "unchanged config"
    sandbox.clear_calls()
    third = sandbox.make_commit("THREE", nginx_extra="# a changed comment\n")
    result = sandbox.run(third)
    assert result.returncode == 0, result.stderr
    assert f"roxy-nginx-apply {third}" in sandbox.calls()
    # ONE went to blue, TWO to green, so THREE goes to blue; the new config is installed before the switch.
    assert sandbox.calls().index(f"roxy-nginx-apply {third}") < sandbox.calls().index("roxy-switch-color blue")
    assert second != third


def sequence(box: DeploySandbox, sha: str) -> int:
    return int((box.releases / sha / ".roxy-release-sequence").read_text().strip())


def test_keeps_the_newest_five_releases(sandbox: DeploySandbox) -> None:
    shas = [deployed(sandbox, f"V{i}") for i in range(7)]
    remaining = sandbox.release_dirs()
    assert len(remaining) == 5
    assert set(shas[-5:]) == set(remaining)
    for color in ("blue", "green"):
        assert sandbox.current(color) in remaining
    assert [sequence(sandbox, sha) for sha in shas[-5:]] == [3, 4, 5, 6, 7]  # one number per deploy, in order


def test_releases_are_kept_by_deploy_order_not_file_time(sandbox: DeploySandbox) -> None:
    """Lane tooling open issue 1: kept releases used to be ordered by the stamp's file time, and a wall clock that
    steps back (NTP; WSL steps about 0.9 s every 31 s) made a newer release look older. Here every stamp's time is
    turned around (the newest release looks oldest): the deploy sequence still removes the oldest release."""
    shas = [deployed(sandbox, f"V{i}") for i in range(6)]  # V0 is already gone; V1 to V5 stay
    assert set(sandbox.release_dirs()) == set(shas[1:])
    base = 1_700_000_000
    for age, sha in enumerate(reversed(shas[1:])):  # V5 gets the oldest stamp, V1 the newest
        stamp = sandbox.releases / sha / ".roxy-release-complete"
        os.utime(stamp, (base - 3600 * age, base - 3600 * age))
    newest = deployed(sandbox, "V6")
    assert set(sandbox.release_dirs()) == {*shas[2:], newest}, "the oldest deploy (V1) goes, whatever its file time"
    # A rollback starts an older release again: it becomes the newest by deploy order, so it is kept next time.
    result = sandbox.run(shas[4], script=sandbox.opt / "deploy_rollback.sh")
    assert result.returncode == 0, result.stdout + result.stderr
    assert sequence(sandbox, shas[4]) == max(sequence(sandbox, sha) for sha in sandbox.release_dirs())
    later = deployed(sandbox, "V7")
    kept = set(sandbox.release_dirs())
    assert shas[4] in kept
    assert shas[2] not in kept  # now the oldest by deploy order
    assert later in kept
    assert len(kept) == 5


def test_releases_from_an_older_deploy_script_sort_before_numbered_ones(sandbox: DeploySandbox) -> None:
    """A release used only by a deploy.sh older than the sequence has no number: it counts as older than every
    numbered release, so the first deploys with this script prune those first, newest stamp kept longest."""
    shas = [deployed(sandbox, f"OLD{i}") for i in range(5)]
    for index, sha in enumerate(shas):
        (sandbox.releases / sha / ".roxy-release-sequence").unlink()
        stamp_time = 1_700_000_000 + 3600 * index  # set, so a clock step during the test cannot reorder them
        os.utime(sandbox.releases / sha / ".roxy-release-complete", (stamp_time, stamp_time))
    newer = [deployed(sandbox, f"NEW{i}") for i in range(2)]
    assert [sequence(sandbox, sha) for sha in newer] == [1, 2]
    kept = set(sandbox.release_dirs())
    assert set(newer) <= kept
    assert len(kept) == 5
    assert not {shas[0], shas[1]} & kept  # the two oldest unnumbered releases went first


# ------------------------------------------------------------------------------------------ failures


def test_v1_3_fetch_failure_must_not_brick_the_server(sandbox: DeploySandbox) -> None:
    """v1 scenario 3: the repository is unreachable; nothing live is touched and deploy.sh survives."""
    first = deployed(sandbox)
    sha = sandbox.make_commit("NEVER_DEPLOYED")
    sandbox.clear_calls()
    result = sandbox.run(sha, ROXY_DEPLOY_REPO_URL=str(sandbox.base / "does-not-exist.git"))
    assert result.returncode != 0
    assert (sandbox.opt / "deploy.sh").exists()
    assert subprocess.run(["bash", "-n", str(sandbox.opt / "deploy.sh")], check=False).returncode == 0
    assert sandbox.active_color() == "blue"
    assert sandbox.running("blue")
    assert sandbox.unit_value("blue", "release") == first
    assert not any("restart" in call or "stop" in call for call in sandbox.calls())
    assert not (sandbox.releases / sha).exists()


def test_v1_4_failed_build_keeps_the_old_release(sandbox: DeploySandbox) -> None:
    """v1 scenarios 4 and 8, plan 19.9 "failed build": uv sync fails; the live color is untouched."""
    first = deployed(sandbox)
    sha = sandbox.make_commit("BROKEN_LOCK")
    sandbox.flag("fail-uv-sync")
    sandbox.clear_calls()
    result = sandbox.run(sha)
    assert result.returncode != 0
    assert "at step 2" in result.stderr
    assert sandbox.active_color() == "blue"
    assert sandbox.running("blue")
    assert sandbox.unit_value("blue", "release") == first
    assert not any("restart" in call for call in sandbox.calls()), "the idle color is never started"
    assert not (sandbox.releases / sha).exists(), "a half-built release is removed"
    assert sandbox.current("green") is None
    record = json.loads((sandbox.deploy_state / "last_failure.json").read_text())
    assert record["step"] == 2
    assert record["sha"] == sha


def test_v1_8_failed_build_leaves_a_usable_environment(sandbox: DeploySandbox) -> None:
    """v1 scenario 8: after a failed build the running release still has its working venv."""
    first = deployed(sandbox)
    sandbox.flag("fail-uv-sync")
    result = sandbox.run(sandbox.make_commit("EXTRA_DEP", lock_extra="extra==1.0"))
    assert result.returncode != 0
    assert (sandbox.releases / first / ".venv" / "bin" / "python").exists()
    assert sandbox.running("blue")


def test_v1_5_commit_missing_required_paths_is_refused(sandbox: DeploySandbox) -> None:
    """v1 scenario 5, with the C5 replacement text: "Clone is missing <x>; refusing to deploy it."."""
    deployed(sandbox)
    sha = sandbox.make_commit("NO_APP", omit=("src/roxy",))
    sandbox.clear_calls()
    result = sandbox.run(sha)
    assert result.returncode != 0
    assert "Clone is missing src/roxy; refusing to deploy it." in result.stderr
    assert sandbox.running("blue")
    assert not any("stop" in call or "restart" in call for call in sandbox.calls()), "never even stopped"


def test_commit_not_on_main_is_refused(sandbox: DeploySandbox) -> None:
    deployed(sandbox)
    side = sandbox.make_commit("SIDE_BRANCH", branch="feature")
    result = sandbox.run(side)
    assert result.returncode != 0
    assert "is not on main in" in result.stderr
    assert "refusing to deploy it." in result.stderr
    assert not (sandbox.releases / side).exists()


def test_repository_credentials_never_reach_the_log_or_the_alert(sandbox: DeploySandbox) -> None:
    """A repository URL with a token in it (https://user:token@host/...) is logged without the user info: the
    deploy log is the Action log, and the failure record becomes the alert email. Port 9 on loopback refuses the
    connection, so nothing leaves the machine and step 1 fails."""
    deployed(sandbox)
    secret = "FAKEtokenVALUE0123456789"
    url = f"https://x-access-token:{secret}@127.0.0.1:9/owner/roxy.git"
    result = sandbox.run(sandbox.make_commit("TOKEN_URL"), ROXY_DEPLOY_REPO_URL=url)
    assert result.returncode != 0
    assert "at step 1" in result.stderr
    assert "from https://127.0.0.1:9/owner/roxy.git (main)" in result.stdout
    record = (sandbox.deploy_state / "last_failure.json").read_text()
    for text in (result.stdout, result.stderr, record):
        assert secret not in text
        assert "x-access-token" not in text


def test_missing_repository_is_explained(sandbox: DeploySandbox) -> None:
    """roxy.env still has the OWNER/REPO placeholder and the workflow passed no ROXY_REPO."""
    result = sandbox.run("a" * 40, ROXY_DEPLOY_REPO_URL="")
    assert result.returncode != 0
    assert "No repository to fetch from" in result.stderr
    record = json.loads((sandbox.deploy_state / "last_failure.json").read_text())
    assert "No repository to fetch from" in record["error"]


def test_commit_removed_from_main_is_refused(sandbox: DeploySandbox) -> None:
    """A commit the mirror already has, but which a force push took off main, fails the ancestry check."""
    deployed(sandbox, "BASE")
    dropped = deployed(sandbox, "DROPPED")
    from deploy_sandbox import git

    git("reset", "--quiet", "--hard", "HEAD~1", cwd=sandbox.work)
    sandbox.make_commit("REWRITTEN")  # force-pushes main without DROPPED
    result = sandbox.run(dropped)
    assert result.returncode != 0
    assert f"Commit {dropped} is not on main; refusing to deploy it." in result.stderr


@pytest.mark.parametrize("bad", ["abc123", "A" * 40, "g" * 40, "1" * 39, "--rollback-ish"])
def test_bad_sha_is_a_usage_error(sandbox: DeploySandbox, bad: str) -> None:
    result = sandbox.run(bad)
    assert result.returncode == 2
    assert not sandbox.calls()


def test_failed_health_gate_rolls_back(sandbox: DeploySandbox) -> None:
    """Plan 19.9 "failed health gate": green starts but never reports Ready; nginx never switches."""
    first = deployed(sandbox)
    sandbox.flag("unhealthy-green")
    sandbox.clear_calls()
    result = sandbox.run(sandbox.make_commit("SICK"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "Health gate failed" in result.stderr
    assert not any(call.startswith("roxy-switch-color") for call in sandbox.calls())
    assert sandbox.current("green") is None, "the idle link is restored (it had no release before)"


def test_wrong_version_fails_the_health_gate(sandbox: DeploySandbox) -> None:
    first = deployed(sandbox)
    sandbox.flag("bad-version-green")
    result = sandbox.run(sandbox.make_commit("WRONG"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)


def test_failed_smoke_test_rolls_back(sandbox: DeploySandbox) -> None:
    first = deployed(sandbox)
    sandbox.flag("smoke-fail")
    result = sandbox.run(sandbox.make_commit("SMOKE"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "Smoke test failed on green." in result.stderr


def test_failed_migration_rolls_back(sandbox: DeploySandbox) -> None:
    """Plan 19.9 "failed migration": the pre-start migration fails, so the start fails; nothing switches."""
    first = deployed(sandbox)
    sandbox.flag("fail-migrate")
    result = sandbox.run(sandbox.make_commit("BAD_MIGRATION"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "at step 4" in result.stderr
    assert "did not start" in result.stderr


def test_failure_after_the_switch_switches_back(sandbox: DeploySandbox) -> None:
    """The new color fails during the 60 s watch: nginx goes back to the old color, the new one stops."""
    first = deployed(sandbox)
    sandbox.flag("unhealthy-after-switch-green")
    sandbox.clear_calls()
    result = sandbox.run(sandbox.make_commit("FLAKY"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "Watch failed" in result.stderr
    calls = sandbox.calls()
    assert calls.index("roxy-switch-color green") < calls.index("roxy-switch-color blue")
    assert "nginx switched back to blue" in (sandbox.deploy_state / "last_failure.json").read_text()


def test_failed_deploy_restores_the_previous_nginx_config(sandbox: DeploySandbox) -> None:
    """A release that changed the nginx config fails after its config was installed: the old color must get its own
    config back, not keep running behind the config of the release that failed."""
    first = deployed(sandbox)
    assert json.loads(sandbox.applied.read_text())["sha"] == first
    sandbox.flag("unhealthy-after-switch-green")
    sandbox.clear_calls()
    sha = sandbox.make_commit("NEW_NGINX", nginx_extra="# a changed nginx config\n")
    result = sandbox.run(sha)
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    applied = json.loads(sandbox.applied.read_text())
    assert applied["sha"] == first, "the config of the release blue runs is installed again"
    assert applied["manifest_sha256"] == sandbox.manifest_hash(first)
    calls = sandbox.calls()
    assert calls.index(f"roxy-nginx-apply {sha}") < calls.index("roxy-switch-color green")
    assert calls.index("roxy-switch-color blue") < calls.index(f"roxy-nginx-apply {first}")
    record = json.loads((sandbox.deploy_state / "last_failure.json").read_text())
    assert f"nginx config restored to {first[:12]}" in record["rollback"]


def test_restore_of_the_nginx_config_falls_back_to_the_active_release(sandbox: DeploySandbox) -> None:
    """applied.json names a release that is gone (pruned): the config of the release the old color runs is
    installed instead (every successful deploy leaves exactly that config installed)."""
    first = deployed(sandbox)
    sandbox.applied.write_text(json.dumps({"sha": "f" * 40, "manifest_sha256": "0" * 64}))
    sandbox.flag("unhealthy-after-switch-green")
    sha = sandbox.make_commit("NEW_NGINX", nginx_extra="# a changed nginx config\n")
    result = sandbox.run(sha)
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert json.loads(sandbox.applied.read_text())["sha"] == first


def test_failed_restore_of_the_nginx_config_is_reported(sandbox: DeploySandbox) -> None:
    first = deployed(sandbox)
    sandbox.flag("unhealthy-after-switch-green")
    sandbox.flag(f"apply-fail-{first}")
    sha = sandbox.make_commit("NEW_NGINX", nginx_extra="# a changed nginx config\n")
    result = sandbox.run(sha)
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert f"run: sudo {sandbox.bin}/roxy-nginx-apply {first}" in result.stderr
    record = json.loads((sandbox.deploy_state / "last_failure.json").read_text())
    assert f"COULD NOT restore the nginx config of {first[:12]}" in record["rollback"]


def test_failed_apply_is_not_undone_by_another_apply(sandbox: DeploySandbox) -> None:
    """A failed apply changed nothing that stays (the wrapper puts its own files back), so there is nothing to
    restore; only the switch back and the stop happen."""
    first = deployed(sandbox)
    sandbox.flag("apply-fail")
    sandbox.clear_calls()
    result = sandbox.run(sandbox.make_commit("APPLY_FAILS", nginx_extra="# changed\n"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert f"roxy-nginx-apply {first}" not in sandbox.calls()


def test_first_deploy_failure_after_the_apply_says_the_config_stays(sandbox: DeploySandbox) -> None:
    sandbox.flag("smoke-nginx-fail")
    sha = sandbox.make_commit("FIRST")
    result = sandbox.run(sha)
    assert result.returncode != 0
    record = json.loads((sandbox.deploy_state / "last_failure.json").read_text())
    assert f"the nginx config of {sha[:12]} stays installed" in record["rollback"]


def test_watch_requires_roxy_v2_to_answer_the_public_health(sandbox: DeploySandbox) -> None:
    """During the cutover v1's nginx site still owns the host name and answers /health with 200. The watch must
    notice that the answer is not Roxy v2's (no Degraded key) instead of passing on v1."""
    first = deployed(sandbox)
    sandbox.flag("public-v1")
    result = sandbox.run(sandbox.make_commit("BEHIND_V1"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "Watch failed" in result.stderr
    assert "not by Roxy v2" in result.stderr
    assert "ROXY_DEPLOY_PUBLIC_CHECK=0" in result.stderr
    record = json.loads((sandbox.deploy_state / "last_failure.json").read_text())
    assert "not by Roxy v2" in record["error"]


def public_checks(box: DeploySandbox) -> list[str]:
    return [call for call in box.calls() if call.startswith("curl ") and "--resolve" in call]


def test_watch_makes_every_check_however_slow_the_checks_are(sandbox: DeploySandbox) -> None:
    """Lane tooling open issue 2: the watch counted whole seconds of the wall clock ($SECONDS), so on a busy machine
    (or across a clock step) a 1 s watch could end after one check, or none. It now makes WATCH_S /
    WATCH_INTERVAL_S checks (here 1 / 0.2 = 5), however long each takes."""
    deployed(sandbox)
    sandbox.flag("slow-public")  # each public answer takes 0.4 s: 5 checks need about 3 s, three times WATCH_S
    sandbox.clear_calls()
    result = sandbox.run(sandbox.make_commit("SLOW_BOX"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(public_checks(sandbox)) == 5
    assert "watching green for 1 s (5 checks, 0.2 s apart)" in result.stdout
    sandbox.clear_calls()
    result = sandbox.run(sandbox.make_commit("SLOW_BOX_2"), ROXY_WATCH_S="1", ROXY_WATCH_INTERVAL_S="0.3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(public_checks(sandbox)) == 4  # rounded up: the watch never spans less than WATCH_S


def test_watch_catches_a_failure_late_in_the_window(sandbox: DeploySandbox) -> None:
    """The public answer turns into v1's after the third check; checks 4 and 5 fail, so the deploy rolls back. A
    watch timed by $SECONDS on a busy machine ended before the fourth check and let this release through."""
    first = deployed(sandbox)
    sandbox.flag("slow-public")
    (sandbox.state / "flags" / "public-v1-after").write_text("3", encoding="utf-8")
    sha = sandbox.make_commit("LATE_FAILURE")
    sandbox.clear_calls()
    result = sandbox.run(sha)
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "Watch failed: 2 failed checks on green" in result.stderr
    assert len(public_checks(sandbox)) == 5  # three good answers, then the fourth and fifth fail


def test_public_check_can_be_skipped_for_a_deploy_before_the_cutover(sandbox: DeploySandbox) -> None:
    sandbox.flag("public-v1")
    sha = sandbox.make_commit("BESIDE_V1")
    result = sandbox.run(sha, ROXY_DEPLOY_PUBLIC_CHECK="0")
    assert result.returncode == 0, result.stdout + result.stderr
    assert sandbox.unit_value("blue", "release") == sha
    assert not any("--resolve" in call for call in sandbox.calls())
    assert not any("--nginx 127.0.0.1:443" in call for call in sandbox.calls())


def test_public_check_failure_when_nginx_gives_no_200(sandbox: DeploySandbox) -> None:
    first = deployed(sandbox)
    sandbox.flag("public-down")
    result = sandbox.run(sandbox.make_commit("PUBLIC_DOWN"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "gave no 200 answer" in result.stderr


def test_failed_smoke_through_nginx_switches_back(sandbox: DeploySandbox) -> None:
    """After the switch, the smoke test runs again through nginx (HSTS on a static asset); a failure rolls back."""
    first = deployed(sandbox)
    sandbox.flag("smoke-nginx-fail")
    result = sandbox.run(sandbox.make_commit("NO_HSTS"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "Smoke test through nginx failed on green." in result.stderr
    assert any("--nginx 127.0.0.1:443" in call for call in sandbox.calls())


def test_failed_switch_rolls_back(sandbox: DeploySandbox) -> None:
    first = deployed(sandbox)
    sandbox.flag("switch-fail")
    result = sandbox.run(sandbox.make_commit("NO_SWITCH"))
    assert result.returncode != 0
    assert sandbox.running("blue")
    assert not sandbox.running("green")
    assert sandbox.unit_value("blue", "release") == first


def test_err_trap_fires_inside_functions(sandbox: DeploySandbox) -> None:
    """v1 bug: a failing command inside a function under `set -e` without `-E` skipped the ERR trap. A failing
    nginx apply (inside switch_traffic) must still roll back."""
    first = deployed(sandbox)
    sandbox.flag("apply-fail")
    result = sandbox.run(sandbox.make_commit("APPLY", nginx_extra="# changed\n"))
    assert_rolled_back(sandbox, result, old="blue", old_sha=first)
    assert "at step 6" in result.stderr


def test_old_color_that_does_not_stop_fails_but_keeps_the_new_one(sandbox: DeploySandbox) -> None:
    """After the switch and watch, a stuck old color is reported; nginx stays on the healthy new color."""
    deployed(sandbox)
    sandbox.flag("stop-hangs-blue")
    sha = sandbox.make_commit("STUCK_OLD")
    result = sandbox.run(sha)
    assert result.returncode != 0
    assert sandbox.active_color() == "green"  # never switched back to a color that may be half stopped
    assert sandbox.unit_value("green", "release") == sha


def test_concurrent_deploy_is_blocked_by_the_lock(sandbox: DeploySandbox) -> None:
    """Plan 19.9: a second deploy while one holds the lock exits at once and changes nothing."""
    first = deployed(sandbox)
    sha = sandbox.make_commit("SECOND")
    lock = sandbox.deploy_state / "lock"
    holder = subprocess.Popen(["flock", str(lock), "-c", "sleep 30"])
    try:
        for _ in range(50):  # wait until the holder has the lock
            probe = subprocess.run(["flock", "-n", str(lock), "true"], check=False)
            if probe.returncode != 0:
                break
            subprocess.run(["sleep", "0.05"], check=False)
        sandbox.clear_calls()
        result = sandbox.run(sha)
    finally:
        holder.kill()
        holder.wait()
    assert result.returncode == 75
    assert "Another deploy is running" in result.stderr
    assert sandbox.calls() == []
    assert sandbox.running("blue")
    assert sandbox.unit_value("blue", "release") == first
    assert not (sandbox.releases / sha).exists()
    assert not (sandbox.deploy_state / "last_failure.json").exists(), "a refused deploy is not a failed deploy"


def test_deploy_as_root_is_refused(sandbox: DeploySandbox, tmp_path: Path) -> None:
    fake_id = tmp_path / "idbin"
    fake_id.mkdir()
    (fake_id / "id").write_text("#!/bin/bash\necho 0\n")
    (fake_id / "id").chmod(0o755)
    result = sandbox.run("a" * 40, PATH=f"{fake_id}:{sandbox.bin}:/usr/bin:/bin")
    assert result.returncode == 2
    assert "not as root" in result.stderr


# ---------------------------------------------------------------------------------------------- rollback


def test_rollback_script_returns_to_the_previous_release(sandbox: DeploySandbox) -> None:
    """Plan 19.9 "rollback": deploy A (blue), deploy B (green), then deploy_rollback.sh brings A back on blue."""
    first = deployed(sandbox, "A")
    second = deployed(sandbox, "B")
    assert sandbox.active_color() == "green"
    sandbox.clear_calls()
    result = sandbox.run(script=sandbox.opt / "deploy_rollback.sh")
    assert result.returncode == 0, result.stdout + result.stderr
    assert sandbox.active_color() == "blue"
    assert sandbox.running("blue")
    assert not sandbox.running("green")
    assert sandbox.unit_value("blue", "release") == first
    assert (sandbox.deploy_state / "deployed_version").read_text().strip() == first
    assert not any(call.startswith("uv ") for call in sandbox.calls()), "a rollback never builds"
    assert sandbox.current("green") == second


def test_rollback_to_a_named_release(sandbox: DeploySandbox) -> None:
    first = deployed(sandbox, "A")
    deployed(sandbox, "B")
    deployed(sandbox, "C")  # blue now runs C, green ran B
    result = sandbox.run(first, script=sandbox.opt / "deploy_rollback.sh")
    assert result.returncode == 0, result.stderr
    assert sandbox.unit_value(sandbox.active_color() or "", "release") == first


def test_rollback_with_nothing_to_go_back_to_fails_cleanly(sandbox: DeploySandbox) -> None:
    deployed(sandbox, "ONLY")
    result = sandbox.run(script=sandbox.opt / "deploy_rollback.sh")
    assert result.returncode != 0
    assert "Nothing to roll back to" in result.stderr
    assert sandbox.running("blue")


def test_failed_rollback_keeps_the_current_color(sandbox: DeploySandbox) -> None:
    deployed(sandbox, "A")
    second = deployed(sandbox, "B")
    sandbox.flag("unhealthy-blue")
    result = sandbox.run(script=sandbox.opt / "deploy_rollback.sh")
    assert_rolled_back(sandbox, result, old="green", old_sha=second)


# ------------------------------------------------------------------------------------------- low memory


def test_low_memory_mode_is_chosen_below_700_mb(sandbox: DeploySandbox) -> None:
    """DESIGN.md section 0: below 700 MB available the idle color starts with 1 worker, and after the old color
    stopped it grows to ROXY_WORKERS through the gunicorn control socket (SIGTTIN's code path)."""
    deployed(sandbox)
    sandbox.set_memory_mb(650)
    sandbox.clear_calls()
    result = sandbox.run(sandbox.make_commit("LOW"))
    assert result.returncode == 0, result.stderr
    assert "Low-memory mode: 650 MB available" in result.stdout
    assert sandbox.unit_value("green", "start_workers") == "1"
    assert sandbox.unit_value("green", "workers") == "2"
    calls = sandbox.calls()
    stop = calls.index("systemctl stop roxy@blue.service")
    add = next(i for i, call in enumerate(calls) if call.startswith("gunicornc") and "worker add 1" in call)
    assert stop < add, "workers are added only after the old color stopped"
    assert any(f"-s {sandbox.root}/run/roxy-green/gunicorn.ctl" in call for call in calls)
    assert not (sandbox.deploy_state / "start-workers-green").exists(), "the marker is removed"


def test_normal_mode_at_700_mb_and_above(sandbox: DeploySandbox) -> None:
    deployed(sandbox)
    sandbox.set_memory_mb(700)
    result = sandbox.run(sandbox.make_commit("ENOUGH"))
    assert result.returncode == 0, result.stderr
    assert "Normal mode: 700 MB available" in result.stdout
    assert sandbox.unit_value("green", "start_workers") == "2"
    assert not any(call.startswith("gunicornc") for call in sandbox.calls())


def test_low_memory_flags_override_the_measurement(sandbox: DeploySandbox) -> None:
    deployed(sandbox)
    result = sandbox.run("--low-memory", sandbox.make_commit("FORCED"))
    assert result.returncode == 0, result.stderr
    assert sandbox.unit_value("green", "start_workers") == "1"
    sandbox.set_memory_mb(100)
    result = sandbox.run("--no-low-memory", sandbox.make_commit("FORCED_OFF"))
    assert result.returncode == 0, result.stderr
    assert sandbox.unit_value("blue", "start_workers") == "2"


def test_low_memory_scale_up_falls_back_to_a_reload(sandbox: DeploySandbox) -> None:
    deployed(sandbox)
    sandbox.set_memory_mb(500)
    sandbox.flag("gunicornc-fail")
    sandbox.clear_calls()
    result = sandbox.run(sandbox.make_commit("NO_CTL"))
    assert result.returncode == 0, result.stderr
    assert "systemctl reload roxy@green.service" in sandbox.calls()
    assert sandbox.unit_value("green", "workers") == "2"


def test_failed_low_memory_deploy_removes_the_marker(sandbox: DeploySandbox) -> None:
    deployed(sandbox)
    sandbox.set_memory_mb(500)
    sandbox.flag("unhealthy-green")
    result = sandbox.run(sandbox.make_commit("LOW_FAIL"))
    assert result.returncode != 0
    assert not (sandbox.deploy_state / "start-workers-green").exists()


def test_first_deploy_never_uses_low_memory_mode(sandbox: DeploySandbox) -> None:
    """With no old color there is no overlap, so the first deploy starts with every worker."""
    sandbox.set_memory_mb(300)
    deployed(sandbox)
    assert sandbox.unit_value("blue", "start_workers") == "2"


# ---------------------------------------------------------------------------------------------- bootstrap


def test_workflow_bootstrap_installs_a_missing_deploy_script(sandbox: DeploySandbox) -> None:
    """Plan 17.4 "Bootstrap (parity)": with /opt/roxy/deploy.sh missing, the workflow's script installs it from
    the pushed commit and runs it. The workflow text is taken from .github/workflows/deploy.yml as is; only the
    install path and the GitHub URL (via git's insteadOf) point into the sandbox."""
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "deploy.yml").read_text())
    step = next(s for s in workflow["jobs"]["deploy"]["steps"] if "ssh-action" in s.get("uses", ""))
    script = step["with"]["script"].replace("/opt/roxy/deploy.sh", str(sandbox.opt / "deploy.sh"))
    (sandbox.opt / "deploy.sh").unlink()
    (sandbox.opt / "deploy_rollback.sh").unlink()
    gh_root = sandbox.remote.parent.parent
    (sandbox.home / ".gitconfig").write_text(f'[url "{gh_root}/"]\n\tinsteadOf = https://github.com/\n')
    sha = sandbox.make_commit("BOOTSTRAPPED")
    env = sandbox.env(ROXY_SHA=sha, ROXY_REPO="owner/roxy")
    env.pop("ROXY_DEPLOY_REPO_URL")  # deploy.sh falls back to https://github.com/$ROXY_REPO.git (rewritten)
    env.pop("GIT_CONFIG_NOSYSTEM")
    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "is missing; installing it" in result.stdout
    assert os.access(sandbox.opt / "deploy.sh", os.X_OK)
    assert sandbox.unit_value("blue", "release") == sha
    assert (sandbox.opt / "deploy_rollback.sh").exists(), "the successful deploy installs its sibling too"


def test_existing_deploy_script_is_used_without_bootstrap(sandbox: DeploySandbox) -> None:
    workflow = yaml.safe_load((REPO / ".github" / "workflows" / "deploy.yml").read_text())
    step = next(s for s in workflow["jobs"]["deploy"]["steps"] if "ssh-action" in s.get("uses", ""))
    script = step["with"]["script"].replace("/opt/roxy/deploy.sh", str(sandbox.opt / "deploy.sh"))
    sha = sandbox.make_commit("NORMAL")
    result = subprocess.run(
        ["bash", "-c", script],
        env=sandbox.env(ROXY_SHA=sha, ROXY_REPO="owner/roxy"),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "is missing" not in result.stdout


def test_alert_record_for_the_deploy_alert_unit(sandbox: DeploySandbox) -> None:
    """A failure writes last_failure.json in the shape alert_on_failure.py reads (plan 17.7 "Deploy failed")."""
    deployed(sandbox)
    sandbox.flag("smoke-fail")
    sha = sandbox.make_commit("ALERT")
    sandbox.run(sha)
    record = json.loads((sandbox.deploy_state / "last_failure.json").read_text())
    assert record["short"] == sha[:12]
    assert record["step"] == 5
    assert record["mode"] == "deploy"
    assert "Smoke test failed" in record["error"]
    assert oct((sandbox.deploy_state / "last_failure.json").stat().st_mode & 0o777) == "0o644"


def test_sandbox_never_uses_the_real_tools(sandbox: DeploySandbox) -> None:
    """Guard for this suite: every privileged command goes through a stub (nothing reaches the real system)."""
    deployed(sandbox)
    sudo_calls = [call for call in sandbox.calls() if call.startswith("sudo ")]
    assert sudo_calls
    assert all(call.startswith(f"sudo {sandbox.bin}/") for call in sudo_calls), sudo_calls
