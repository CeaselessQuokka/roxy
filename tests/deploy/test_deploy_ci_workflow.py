"""The GitHub workflows: what CI runs, how it is hardened, and that deploy.yml stays disabled (plan 9.14, 17.4).

What this is
    Static checks of .github/workflows/ci.yml and deploy.yml: every check the plan asks CI to run has its job and
    command (lint, types, unit, integration, multiprocess, security, migration, the deploy sandbox, Playwright,
    the writing style on the repository and on rendered pages, gitleaks, pip-audit, shellcheck, `nginx -t` with the
    distro nginx of Ubuntu 22.04 and 24.04 and `systemd-analyze verify` in containers, the generated settings
    reference, the LLM export schema and the v1 parity table); every test directory runs in some job; every test
    id and script the workflow names exists; actions are pinned by commit; the token is read only; checkout keeps
    no credentials; uv always installs the lock; and the deploy job keeps its `if: false`.

Why it exists
    A workflow is code nobody runs locally: a typo in a test id, a renamed script or a suite that no job names
    passes review and then silently checks nothing. Plan 9.14 also makes the workflow part of the supply chain
    (pinned actions, least privilege), and plan 17.4 says the deploy must not run until the owner removes its guard.

How it works
    The YAML is parsed with PyYAML (which reads the key `on` as True) and the raw text is searched where the
    structure does not matter (pins, test ids, script paths). Test ids are checked by file and function name.

What to read next
    .github/workflows/ci.yml, .github/workflows/deploy.yml, then tests/deploy/test_deploy_advisories.py.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from deploy_sandbox import DEPLOY, REPO

pytestmark = [pytest.mark.deploy]

WORKFLOWS = REPO / ".github" / "workflows"
CI_TEXT = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
DEPLOY_TEXT = (WORKFLOWS / "deploy.yml").read_text(encoding="utf-8")
CI: dict[Any, Any] = yaml.safe_load(CI_TEXT)
DEPLOY_WORKFLOW: dict[Any, Any] = yaml.safe_load(DEPLOY_TEXT)

REQUIRED: dict[str, tuple[str, ...]] = {
    "lint": (
        "uv run --frozen ruff check src tests scripts",
        "uv run --frozen ruff format --check src tests scripts",
        "uv run --frozen mypy",
        "scripts/ctl.py scripts/shadow_report.py",
        "scripts/gen_settings_docs.py --check",
        "roxy.insights.llm_export --write-schema",
        "diff -u src/roxy/insights/schema/llm_export.v1.schema.json",
        "Draft202012Validator.check_schema",
        "scripts/gen_v1_parity.py --check",
    ),
    "style": (
        "scripts/check_style.py\n",
        "scripts/check_style.py REMAKE_PLAN.md",
        "test_no_dash_characters_in_rendered_pages",
        "test_auth_pages_obey_the_csp_and_the_writing_style",
    ),
    "unit": ("pytest -p no:cacheprovider tests --ignore=",),
    "integration": ("pytest -p no:cacheprovider tests/integration",),
    "multiprocess": ("pytest -p no:cacheprovider tests/multiprocess",),
    "security": ("pytest -p no:cacheprovider tests/security", "bandit -c pyproject.toml -r src -ll"),
    "migration": ("pytest -p no:cacheprovider tests/migration",),
    "deploy": ("shellcheck zstd age nginx", "tests/deploy"),
    "shellcheck": ("shellcheck --severity=style",),
    "config-lint": ("test_nginx_t_accepts_the_rendered_site[nginx-$NGINX_LABEL]", "test_systemd_analyze_verify"),
    "e2e": ("playwright install --with-deps chromium", "pytest -p no:cacheprovider tests/e2e"),
    "dependency-audit": (
        "pip-audit --skip-editable --format json",
        "uv export --frozen --no-dev --no-emit-project",
        "pip-audit -r prod-requirements.txt --no-deps --disable-pip",
        "sys.exit(1 if fixable else 0)",
    ),
    "gitleaks": ("gitleaks/v8@v8.", 'gitleaks" git --redact'),
}


def job_text(name: str) -> str:
    """Everything a job runs or names, as one text (steps' names, `run` scripts and inputs)."""
    job = CI["jobs"][name]
    parts: list[str] = [str(job.get("name", ""))]
    for step in job.get("steps", []):
        parts.append(str(step.get("name", "")))
        parts.append(str(step.get("run", "")) + "\n")
        parts.append(str(step.get("uses", "")))
    return "\n".join(parts)


@pytest.mark.parametrize("job", sorted(REQUIRED))
def test_every_required_check_has_its_job(job: str) -> None:
    text = job_text(job)
    missing = [needle for needle in REQUIRED[job] if needle not in text]
    assert missing == [], f"job {job} lacks {missing}"


def test_no_job_is_left_unchecked() -> None:
    assert set(CI["jobs"]) == set(REQUIRED), "a new job needs its expectations here"


def test_every_test_directory_runs_in_ci() -> None:
    """A suite no job names never runs; the unit job runs `tests` minus the suites with their own job."""
    unit = job_text("unit")
    ignored = set(re.findall(r"--ignore=(tests/[\w/]+)", unit))
    dedicated = {
        "tests/integration": "integration",
        "tests/multiprocess": "multiprocess",
        "tests/security": "security",
        "tests/migration": "migration",
        "tests/deploy": "deploy",
        "tests/e2e": "e2e",
    }
    assert ignored == {*dedicated, "tests/load"}
    for directory, job in dedicated.items():
        assert directory in job_text(job), f"{directory} is ignored by the unit job but job {job} does not run it"


def test_actions_are_pinned_by_commit() -> None:
    for text in (CI_TEXT, DEPLOY_TEXT):
        for line in text.splitlines():
            found = re.search(r"uses:\s*(\S+)", line)
            if found is None or found.group(1).startswith("./"):
                continue
            assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", found.group(1)), line
            assert re.search(r"# v\d", line), f"say which release the pinned commit is: {line.strip()}"


def test_the_token_is_read_only_everywhere() -> None:
    for workflow in (CI, DEPLOY_WORKFLOW):
        assert workflow["permissions"] == {"contents": "read"}
        for name, job in workflow["jobs"].items():
            for scope, level in (job.get("permissions") or {}).items():
                assert level in ("read", "none"), f"job {name} asks {scope}: {level}"


def test_checkout_never_keeps_credentials() -> None:
    for job in CI["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_uv_always_installs_exactly_the_lock() -> None:
    for line in CI_TEXT.splitlines():
        command = line.split("#", 1)[0]
        if re.search(r"\buv (sync|run)\b", command):
            assert "--frozen" in command, line.strip()


def test_triggers() -> None:
    triggers = CI[True]
    assert set(triggers) == {"pull_request", "push", "workflow_call"}
    assert triggers["push"] == {"branches-ignore": ["main"]}, "main runs CI through deploy.yml, once"
    assert DEPLOY_WORKFLOW[True] == {"push": {"branches": ["main"]}}


def test_deploy_stays_disabled_until_the_cutover() -> None:
    job = DEPLOY_WORKFLOW["jobs"]["deploy"]
    assert job["if"] is False
    assert "if: false" in DEPLOY_TEXT
    assert job["needs"] == "ci"
    assert DEPLOY_WORKFLOW["jobs"]["ci"]["uses"] == "./.github/workflows/ci.yml"
    assert DEPLOY_WORKFLOW["concurrency"] == {"group": "deploy-production", "cancel-in-progress": False}
    assert job["environment"] == "production"
    step = job["steps"][0]
    assert step["with"]["fingerprint"] == "${{ secrets.LIGHTSAIL_HOST_FINGERPRINT }}", "pinned host key (9.14)"


def test_ci_reads_no_secret() -> None:
    assert "secrets." not in CI_TEXT


def test_named_test_ids_exist() -> None:
    ids = set(re.findall(r"(tests/[\w/]+\.py)::(\w+)", CI_TEXT))
    assert ids, "the workflow names test ids"
    for path, name in sorted(ids):
        source = REPO / path
        assert source.is_file(), path
        assert re.search(rf"^(async )?def {name}\(", source.read_text(encoding="utf-8"), re.MULTILINE), (
            f"{path}::{name}"
        )


def test_named_scripts_and_directories_exist() -> None:
    for script in sorted(set(re.findall(r"\bscripts/[\w-]+\.py\b", CI_TEXT))):
        assert (REPO / script).is_file(), script
    for directory in sorted(set(re.findall(r"\btests/[a-z_]+(?=[\s/]|$)", CI_TEXT, re.MULTILINE))):
        if directory != "tests/load":
            assert (REPO / directory).exists(), directory


def test_shellcheck_covers_every_deploy_shell_script() -> None:
    text = job_text("shellcheck")
    for path in sorted(DEPLOY.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.read_bytes().startswith(b"#!/bin/bash"):
            assert str(path.relative_to(REPO)) in text, f"shellcheck does not look at {path.relative_to(REPO)}"


def test_config_lint_runs_in_the_two_ubuntu_releases() -> None:
    job = CI["jobs"]["config-lint"]
    assert job["container"]["image"] == "${{ matrix.image }}"
    matrix = {row["image"]: row for row in job["strategy"]["matrix"]["include"]}
    assert set(matrix) == {"ubuntu:22.04", "ubuntu:24.04"}
    assert matrix["ubuntu:22.04"]["nginx"] == "1.18"
    assert matrix["ubuntu:24.04"]["nginx"] == "1.24"
    assert matrix["ubuntu:24.04"]["systemd"] is True, "systemd-analyze runs on the production release"
    assert job["strategy"]["fail-fast"] is False
    text = job_text("config-lint")
    assert 'grep -q "PASSED tests/deploy/test_deploy_nginx.py' in text, "a skipped nginx -t must not pass"


def test_the_workflows_follow_the_writing_style() -> None:
    files = [str(path) for path in WORKFLOWS.glob("*.yml")]
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "check_style.py"), *files], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_workflows_have_unix_line_endings() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        data = path.read_bytes()
        assert b"\r\n" not in data
        assert data.endswith(b"\n")
        assert b"\t" not in data, f"{path.name}: YAML indents with spaces"


def test_inline_python_compiles() -> None:
    """The Python the jobs run from heredocs (`python3 - <<'PY'`) must at least parse."""
    blocks = 0
    for job in CI["jobs"].values():
        for step in job.get("steps", []):
            run = str(step.get("run", ""))
            for code in re.findall(r"<<'PY'\n(.*?)\nPY\b", run, re.DOTALL):
                compile(code, f"<{step.get('name')}>", "exec")
                blocks += 1
    assert blocks >= 2


def test_the_ci_header_lists_every_job() -> None:
    header = CI_TEXT.split("\nname:", 1)[0]
    for name in CI["jobs"]:
        assert f"#   {name} " in header, f"the header comment does not describe job {name}"


def test_paths_used_here_are_the_repository_layout() -> None:
    assert Path(WORKFLOWS / "ci.yml").is_file()
    assert (REPO / "src" / "roxy" / "insights" / "schema" / "llm_export.v1.schema.json").is_file()
