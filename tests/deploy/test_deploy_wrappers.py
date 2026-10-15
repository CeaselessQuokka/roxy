"""The root wrappers and the sudo rules: what the deploy user can make root do, and nothing more (plan 9.14).

What this is
    Tests for deploy/tools/roxy-nginx-apply, deploy/tools/roxy-switch-color and deploy/sudoers/roxy-deploy. The
    wrappers run as functions with a `Layout` pointing into a temporary tree, with stub `nginx` and `systemctl`
    programs (and once with the real nginx inside a private namespace), so no test needs root or touches /etc.

Why it exists
    These two programs are the only path from the deploy user to root. The tests pin the promises in their
    docstrings: only a commit on the configured branch is installed, the bytes come from git (not the
    deploy-owned release), a tampered release or manifest is refused, a failed `nginx -t` puts every file back, the
    switch is atomic and reverted on failure, and every `sudo` call deploy.sh makes is allowed by the sudoers file
    while the file allows nothing else.

How it works
    `WrapperTree` makes a git repository with the real deploy/nginx files, a bare "GitHub" copy, a release
    directory built the way deploy.sh builds it (`git archive` and the same `sha256sum` pipeline for the
    manifest), a root-trusted roxy.env (trusted_uid is the test user), and stub programs that log their calls.

What to read next
    deploy/tools/roxy-nginx-apply, deploy/tools/roxy-switch-color, deploy/sudoers/roxy-deploy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from deploy_sandbox import (
    DEPLOY,
    DeploySandbox,
    build_prefix,
    can_unshare,
    git,
    load_script,
    nginx_binaries,
    write_exec,
)

pytestmark = [pytest.mark.deploy]

HOST = "roxy.example.test"


@pytest.fixture(scope="module")
def apply_mod() -> ModuleType:
    return load_script(DEPLOY / "tools" / "roxy-nginx-apply", "roxy_nginx_apply_for_wrapper_tests")


@pytest.fixture(scope="module")
def switch_mod() -> ModuleType:
    return load_script(DEPLOY / "tools" / "roxy-switch-color", "roxy_switch_color_for_wrapper_tests")


STUB_NGINX = r"""
#!/bin/bash
echo "nginx $*" >>"$(dirname "$0")/calls.log"
for arg in "$@"; do
  case "$arg" in
    -v) echo "nginx version: nginx/1.24.0 (Ubuntu)" >&2; exit 0 ;;
    -t) if [ -e "$(dirname "$0")/nginx-t-fails" ]; then echo "nginx: [emerg] unknown directive" >&2; exit 1; fi
        echo "nginx: configuration file test is successful" >&2; exit 0 ;;
    -T) printf 'worker_processes 2;\nevents {\n    worker_connections 4096;\n}\n'; exit 0 ;;
  esac
done
exit 0
"""

STUB_SYSTEMCTL = r"""
#!/bin/bash
echo "systemctl $*" >>"$(dirname "$0")/calls.log"
[ -e "$(dirname "$0")/systemctl-fails" ] && exit 1
exit 0
"""


class WrapperTree:
    """A temporary layout for the wrappers: repository, release, /etc/roxy, /etc/nginx, stub programs."""

    def __init__(self, base: Path, apply_mod: ModuleType) -> None:
        self.base = base
        self.work = base / "work"
        self.remote = base / "remote.git"
        self.releases = base / "releases"
        self.nginx = base / "nginx"
        self.etc = base / "etc"
        self.bin = base / "bin"
        for directory in (self.work, self.releases, self.nginx, self.etc, self.bin):
            directory.mkdir(parents=True)
        git("init", "--quiet", "--bare", "--initial-branch=main", str(self.remote), cwd=base)
        git("init", "--quiet", "--initial-branch=main", cwd=self.work)
        write_exec(self.bin / "nginx", STUB_NGINX)
        write_exec(self.bin / "systemctl", STUB_SYSTEMCTL)
        (self.bin / "calls.log").touch()
        self.write_env(f"ROXY_DEPLOY_REPO_URL={self.remote}\nROXY_SITE_ORIGIN=https://{HOST}\n")
        self.layout = apply_mod.Layout(
            roxy_env=self.etc / "roxy.env",
            releases_dir=self.releases,
            nginx_dir=self.nginx,
            state_dir=base / "state",
            hints_file=self.etc / "nginx-hints.env",
            log_dir=base / "logs",
            cert_root=base / "certs",
            nginx_cmd=(str(self.bin / "nginx"),),
            systemctl_cmd=(str(self.bin / "systemctl"),),
            git_cmd=("git",),
            trusted_uid=os.getuid(),
        )

    def write_env(self, text: str) -> None:
        path = self.etc / "roxy.env"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o640)

    def commit(self, *, extra: str = "", branch: str = "main", symlink: bool = False) -> str:
        nginx = self.work / "deploy" / "nginx"
        if nginx.exists():
            shutil.rmtree(nginx)
        shutil.copytree(DEPLOY / "nginx", nginx)
        if extra:
            snippet = nginx / "snippets" / "roxy-security-headers.conf"
            snippet.write_text(snippet.read_text() + extra)
        if symlink:
            (nginx / "evil.conf").symlink_to("/etc/shadow")
        if branch != "main":
            git("checkout", "--quiet", "-B", branch, cwd=self.work)
        git("add", "--all", cwd=self.work)
        git("commit", "--quiet", "--allow-empty", "-m", f"c {extra}", cwd=self.work)
        sha = git("rev-parse", "HEAD", cwd=self.work)
        git("push", "--quiet", "--force", str(self.remote), f"HEAD:refs/heads/{branch}", cwd=self.work)
        if branch != "main":
            git("checkout", "--quiet", "main", cwd=self.work)
        return sha

    def build_release(self, sha: str) -> Path:
        """The release exactly as deploy.sh step 1 makes it: git archive, then the sha256sum manifest."""
        release = self.releases / sha
        release.mkdir()
        archive = subprocess.run(
            ["git", "--git-dir", str(self.remote), "archive", sha], capture_output=True, check=True
        )
        subprocess.run(["tar", "-x", "-C", str(release)], input=archive.stdout, check=True)
        manifest = subprocess.run(
            [
                "bash",
                "-c",
                'cd "$1" && find deploy/nginx -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum',
                "_",
                str(release),
            ],
            capture_output=True,
            check=True,
        )
        (release / ".roxy-nginx-manifest").write_bytes(manifest.stdout)
        return release

    def calls(self) -> list[str]:
        return (self.bin / "calls.log").read_text().splitlines()


@pytest.fixture
def tree(tmp_path: Path, apply_mod: ModuleType) -> WrapperTree:
    return WrapperTree(tmp_path, apply_mod)


# --------------------------------------------------------------------------------------- roxy-nginx-apply


def test_apply_installs_the_verified_files(tree: WrapperTree, apply_mod: ModuleType) -> None:
    sha = tree.commit()
    release = tree.build_release(sha)
    apply_mod.apply(tree.layout, sha, initial_color="green")
    for name in ("roxy-upstream-blue.conf", "roxy-upstream-green.conf", "snippets/roxy-security-headers.conf"):
        assert (tree.nginx / name).read_bytes() == (DEPLOY / "nginx" / name).read_bytes()
        assert (tree.nginx / name).stat().st_mode & 0o777 == 0o644
    site = (tree.nginx / "sites-available" / "roxy-v2.conf").read_text()
    assert site.startswith(f"# Rendered by roxy-nginx-apply from deploy/nginx/roxy.conf.template at {sha[:12]}")
    assert f"server_name {HOST} www.{HOST};" in site
    assert "{{" not in site
    assert os.readlink(tree.nginx / "sites-enabled" / "roxy-v2.conf") == "../sites-available/roxy-v2.conf"
    assert os.readlink(tree.nginx / "roxy-active-upstream.conf") == str(tree.nginx / "roxy-upstream-green.conf")
    applied = json.loads((tree.base / "state" / "applied.json").read_text())
    manifest = (release / ".roxy-nginx-manifest").read_bytes()
    assert applied["sha"] == sha
    assert applied["manifest_sha256"] == hashlib.sha256(manifest).hexdigest()
    assert (tree.etc / "nginx-hints.env").read_text().splitlines()[1:] == [
        "ROXY_NGINX_WORKER_CONNECTIONS=4096",
        "ROXY_NGINX_WORKER_PROCESSES=2",
    ]
    calls = tree.calls()
    assert calls.index("nginx -t") < calls.index("systemctl reload-or-restart nginx")
    assert (tree.base / "state" / "repo.git").stat().st_mode & 0o777 == 0o700, "the mirror is private"


def test_apply_manifest_matches_deploy_sh_format(tree: WrapperTree, apply_mod: ModuleType) -> None:
    """deploy.sh writes the manifest with sha256sum; the wrapper must compute the identical text from git."""
    sha = tree.commit()
    release = tree.build_release(sha)
    files = apply_mod.fetch_verified(tree.layout, str(tree.remote), "main", sha)
    assert apply_mod.manifest_text(files) == (release / ".roxy-nginx-manifest").read_text()
    deploy_sh = (DEPLOY / "deploy.sh").read_text()
    assert "find deploy/nginx -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum" in deploy_sh


def test_apply_keeps_an_existing_active_color(tree: WrapperTree, apply_mod: ModuleType) -> None:
    first = tree.commit()
    tree.build_release(first)
    apply_mod.apply(tree.layout, first, initial_color="blue")
    second = tree.commit(extra="# two\n")
    tree.build_release(second)
    apply_mod.apply(tree.layout, second, initial_color="green")  # ignored: a color is already active
    assert os.readlink(tree.nginx / "roxy-active-upstream.conf").endswith("roxy-upstream-blue.conf")
    assert "# two" in (tree.nginx / "snippets" / "roxy-security-headers.conf").read_text()


def test_apply_refuses_a_commit_that_is_not_on_main(tree: WrapperTree, apply_mod: ModuleType) -> None:
    tree.commit()
    side = tree.commit(extra="# side\n", branch="feature")
    tree.build_release(side)
    with pytest.raises(apply_mod.ApplyError, match=r"not on main|does not exist"):
        apply_mod.apply(tree.layout, side)
    assert not (tree.nginx / "sites-available").exists()


def test_apply_refuses_a_tampered_release_file(tree: WrapperTree, apply_mod: ModuleType) -> None:
    sha = tree.commit()
    release = tree.build_release(sha)
    target = release / "deploy" / "nginx" / "snippets" / "roxy-security-headers.conf"
    target.write_text("access_log /etc/cron.d/owned;\n")
    with pytest.raises(apply_mod.ApplyError, match="refusing"):
        apply_mod.apply(tree.layout, sha)
    assert not (tree.nginx / "snippets").exists()


def test_apply_refuses_a_tampered_manifest(tree: WrapperTree, apply_mod: ModuleType) -> None:
    sha = tree.commit()
    release = tree.build_release(sha)
    (release / ".roxy-nginx-manifest").write_text("0" * 64 + "  deploy/nginx/roxy.conf.template\n")
    with pytest.raises(apply_mod.ApplyError, match="manifest"):
        apply_mod.apply(tree.layout, sha)


def test_apply_never_installs_from_the_release_directory(tree: WrapperTree, apply_mod: ModuleType) -> None:
    """Even when the release and its manifest are rewritten consistently, the bytes installed come from git, and
    the mismatch with git is refused."""
    sha = tree.commit()
    release = tree.build_release(sha)
    evil = release / "deploy" / "nginx" / "roxy-upstream-blue.conf"
    evil.write_text("access_log /etc/cron.d/owned;\n")
    manifest = subprocess.run(
        [
            "bash",
            "-c",
            'cd "$1" && find deploy/nginx -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum',
            "_",
            str(release),
        ],
        capture_output=True,
        check=True,
    )
    (release / ".roxy-nginx-manifest").write_bytes(manifest.stdout)
    with pytest.raises(apply_mod.ApplyError):
        apply_mod.apply(tree.layout, sha)
    assert not (tree.nginx / "roxy-upstream-blue.conf").exists()


def test_apply_never_follows_links_in_the_release(tree: WrapperTree, apply_mod: ModuleType, tmp_path: Path) -> None:
    """Root reads the deploy-owned release only to compare it, and never through a symlink, even one pointing at a
    file with the right content."""
    sha = tree.commit()
    release = tree.build_release(sha)
    target = release / "deploy" / "nginx" / "roxy-upstream-blue.conf"
    copy = tmp_path / "same-content.conf"
    copy.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(copy)
    with pytest.raises(apply_mod.ApplyError, match="link"):
        apply_mod.apply(tree.layout, sha)


def test_apply_refuses_links_in_the_commit(tree: WrapperTree, apply_mod: ModuleType) -> None:
    sha = tree.commit(symlink=True)
    with pytest.raises(apply_mod.ApplyError, match="not a plain file"):
        apply_mod.apply(tree.layout, sha)


@pytest.mark.parametrize("problem", ["group-writable", "symlink", "other-owner", "placeholder", "missing-url"])
def test_apply_refuses_an_untrusted_roxy_env(tree: WrapperTree, apply_mod: ModuleType, problem: str) -> None:
    sha = tree.commit()
    tree.build_release(sha)
    layout = tree.layout
    env = tree.etc / "roxy.env"
    if problem == "group-writable":
        env.chmod(0o660)
    elif problem == "symlink":
        real = tree.etc / "real.env"
        env.rename(real)
        env.symlink_to(real)
    elif problem == "other-owner":
        layout = apply_mod.Layout(**{**layout.__dict__, "trusted_uid": os.getuid() + 1})
    elif problem == "placeholder":
        tree.write_env("ROXY_DEPLOY_REPO_URL=https://github.com/OWNER/REPO.git\n")
    else:
        tree.write_env(f"ROXY_SITE_ORIGIN=https://{HOST}\n")
    with pytest.raises(apply_mod.ApplyError):
        apply_mod.apply(layout, sha)
    assert not (tree.nginx / "sites-available").exists()


def test_failed_nginx_test_restores_the_previous_config(tree: WrapperTree, apply_mod: ModuleType) -> None:
    first = tree.commit()
    tree.build_release(first)
    apply_mod.apply(tree.layout, first, initial_color="blue")
    before = {p: p.read_bytes() for p in tree.nginx.rglob("*.conf") if p.is_file() and not p.is_symlink()}
    second = tree.commit(extra="# broken\n")
    tree.build_release(second)
    (tree.bin / "nginx-t-fails").touch()
    with pytest.raises(apply_mod.ApplyError, match="nginx -t failed"):
        apply_mod.apply(tree.layout, second)
    after = {p: p.read_bytes() for p in tree.nginx.rglob("*.conf") if p.is_file() and not p.is_symlink()}
    assert after == before
    assert os.readlink(tree.nginx / "roxy-active-upstream.conf").endswith("roxy-upstream-blue.conf")
    assert json.loads((tree.base / "state" / "applied.json").read_text())["sha"] == first


def test_failed_first_apply_leaves_nothing_behind(tree: WrapperTree, apply_mod: ModuleType) -> None:
    sha = tree.commit()
    tree.build_release(sha)
    (tree.bin / "nginx-t-fails").touch()
    with pytest.raises(apply_mod.ApplyError):
        apply_mod.apply(tree.layout, sha, initial_color="blue")
    leftovers = [p for p in tree.nginx.rglob("*") if p.is_file() or p.is_symlink()]
    assert leftovers == []


def test_apply_command_line(tree: WrapperTree, apply_mod: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    sha = tree.commit()
    tree.build_release(sha)
    assert apply_mod.main(["not-a-sha"], layout=tree.layout) == 1
    assert "40 lowercase hex" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        apply_mod.main([sha, "--initial-color", "purple"], layout=tree.layout)
    assert apply_mod.main([sha, "--initial-color", "blue"], layout=tree.layout) == 0


def test_apply_with_the_real_nginx(tree: WrapperTree, apply_mod: ModuleType, tmp_path: Path) -> None:
    """End to end with nginx 1.24 inside a private user and network namespace (ports 80 and 443)."""
    info = next(item for item in nginx_binaries() if item[0] == "1.24")
    _, binary, base, _ = info
    if binary is None or not can_unshare():
        pytest.skip("needs the nginx 1.24 binary and unprivileged user namespaces")
    prefix = tmp_path / "etc-nginx"
    build_prefix(prefix, base.read_text() if base.is_file() else "", namespaced=True)
    for path in (
        prefix / "roxy-active-upstream.conf",
        prefix / "snippets" / "roxy-security-headers.conf",
        prefix / "roxy-upstream-blue.conf",
        prefix / "roxy-upstream-green.conf",
    ):
        path.unlink()  # the wrapper installs these itself
    nginx = (
        "unshare",
        "-rn",
        binary,
        "-p",
        f"{prefix}/",
        "-c",
        str(prefix / "nginx.conf"),
        "-e",
        str(prefix / "logs" / "startup.log"),
    )
    layout = apply_mod.Layout(
        **{
            **tree.layout.__dict__,
            "nginx_dir": prefix,
            "nginx_cmd": nginx,
            "cert_root": prefix / "certs",
            "log_dir": prefix / "logs",
        }
    )
    sha = tree.commit()
    tree.build_release(sha)
    apply_mod.apply(layout, sha, initial_color="blue")
    assert (prefix / "sites-enabled" / "roxy-v2.conf").is_symlink()
    hints = (tree.etc / "nginx-hints.env").read_text()
    assert "ROXY_NGINX_WORKER_CONNECTIONS=768" in hints  # Ubuntu's default, read back with nginx -T


# ------------------------------------------------------------------------------------- roxy-switch-color


@pytest.fixture
def switch_layout(tmp_path: Path, switch_mod: ModuleType) -> Any:
    nginx = tmp_path / "nginx"
    nginx.mkdir()
    for color in ("blue", "green"):
        shutil.copy(DEPLOY / "nginx" / f"roxy-upstream-{color}.conf", nginx)
        (nginx / f"roxy-upstream-{color}.conf").chmod(0o644)
    bin_dir = tmp_path / "bin"
    write_exec(bin_dir / "nginx", STUB_NGINX)
    write_exec(bin_dir / "systemctl", STUB_SYSTEMCTL)
    (bin_dir / "calls.log").touch()
    return switch_mod.Layout(
        nginx_dir=nginx,
        state_dir=tmp_path / "state",
        nginx_cmd=(str(bin_dir / "nginx"),),
        systemctl_cmd=(str(bin_dir / "systemctl"),),
        trusted_uid=os.getuid(),
    )


def test_switch_repoints_tests_and_reloads(switch_mod: ModuleType, switch_layout: ModuleType) -> None:
    switch_mod.switch(switch_layout, "green")
    assert switch_mod.active_color(switch_layout) == "green"
    switch_mod.switch(switch_layout, "blue")
    assert switch_mod.active_color(switch_layout) == "blue"
    calls = (Path(switch_layout.nginx_cmd[0]).parent / "calls.log").read_text().splitlines()
    assert calls == ["nginx -t", "systemctl reload nginx", "nginx -t", "systemctl reload nginx"]
    assert not list(switch_layout.nginx_dir.glob(".*.new"))


def test_switch_restores_the_old_color_when_nginx_t_fails(switch_mod: ModuleType, switch_layout: ModuleType) -> None:
    switch_mod.switch(switch_layout, "blue")
    (Path(switch_layout.nginx_cmd[0]).parent / "nginx-t-fails").touch()
    with pytest.raises(switch_mod.SwitchError, match="previous color was restored"):
        switch_mod.switch(switch_layout, "green")
    assert switch_mod.active_color(switch_layout) == "blue"


def test_switch_refuses_untrusted_upstream_files(switch_mod: ModuleType, switch_layout: ModuleType) -> None:
    (switch_layout.nginx_dir / "roxy-upstream-green.conf").chmod(0o666)
    with pytest.raises(switch_mod.SwitchError, match="not writable"):
        switch_mod.switch(switch_layout, "green")
    with pytest.raises(switch_mod.SwitchError):
        switch_mod.switch(switch_layout, "purple")


def test_switch_refuses_a_regular_file_as_the_link(switch_mod: ModuleType, switch_layout: ModuleType) -> None:
    switch_layout.active_link.write_text("upstream x {}\n")
    with pytest.raises(switch_mod.SwitchError, match="not a symlink"):
        switch_mod.switch(switch_layout, "green")


def test_boot_starts_the_active_color(switch_mod: ModuleType, switch_layout: ModuleType) -> None:
    calls = Path(switch_layout.nginx_cmd[0]).parent / "calls.log"
    switch_mod.boot(switch_layout)  # nothing deployed yet: nothing to start
    assert "start" not in calls.read_text()
    switch_mod.switch(switch_layout, "green")
    switch_mod.boot(switch_layout)
    assert calls.read_text().splitlines()[-1] == "systemctl start roxy@green.service"


def test_switch_command_line(switch_mod: ModuleType, switch_layout: ModuleType) -> None:
    assert switch_mod.main(["blue"], layout=switch_layout) == 0
    assert switch_mod.main(["--boot"], layout=switch_layout) == 0
    for bad in (["purple"], [], ["blue", "--boot"]):
        with pytest.raises(SystemExit):
            switch_mod.main(bad, layout=switch_layout)


def test_wrappers_refuse_to_run_without_root() -> None:
    for name in ("roxy-nginx-apply", "roxy-switch-color"):
        if os.geteuid() == 0:
            pytest.skip("running as root")
        result = subprocess.run(
            ["/usr/bin/python3", str(DEPLOY / "tools" / name), "blue"], capture_output=True, text=True, check=False
        )
        assert result.returncode == 1
        assert "must run as root" in result.stderr


def test_wrappers_use_only_the_standard_library() -> None:
    """They run with /usr/bin/python3 -I as root: no third-party import may sneak in."""
    allowed = {
        "argparse",
        "contextlib",
        "fcntl",
        "hashlib",
        "json",
        "os",
        "re",
        "stat",
        "subprocess",
        "sys",
        "tempfile",
        "time",
        "collections",
        "dataclasses",
        "pathlib",
        "__future__",
    }
    for name in ("roxy-nginx-apply", "roxy-switch-color"):
        text = (DEPLOY / "tools" / name).read_text()
        assert text.startswith("#!/usr/bin/python3 -I\n")
        imported = set(re.findall(r"^(?:from|import) ([a-z_]+)", text, re.MULTILINE))
        assert imported <= allowed, imported - allowed


# ----------------------------------------------------------------------------------------------- sudoers

SUDOERS = DEPLOY / "sudoers" / "roxy-deploy"


def sudoers_rules() -> tuple[set[str], list[re.Pattern[str]]]:
    """Exact commands and argument patterns from the Cmnd_Alias lines (continuations joined)."""
    text = SUDOERS.read_text().replace("\\\n", " ")
    exact: set[str] = set()
    patterns: list[re.Pattern[str]] = []
    for line in text.splitlines():
        if not line.startswith("Cmnd_Alias"):
            continue
        for command in line.split("=", 1)[1].split(","):
            command = " ".join(command.split())
            program, _, args = command.partition(" ")
            if args.startswith("^"):
                patterns.append(re.compile(re.escape(program) + " " + args[1:-1] + "$"))
            else:
                exact.add(command)
    return exact, patterns


def test_sudoers_parses_with_visudo() -> None:
    visudo = shutil.which("visudo") or ("/usr/sbin/visudo" if Path("/usr/sbin/visudo").exists() else None)
    if visudo is None:
        pytest.skip("visudo is not installed")
    result = subprocess.run([visudo, "-c", "-f", str(SUDOERS)], capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    assert "parsed OK" in output, output
    assert "error" not in output.lower(), output


def test_sudoers_allows_only_the_wrappers_and_the_color_units() -> None:
    exact, patterns = sudoers_rules()
    programs = {command.split()[0] for command in exact} | {p.pattern.split(" ")[0].replace("\\", "") for p in patterns}
    assert programs == {"/usr/local/sbin/roxy-switch-color", "/usr/local/sbin/roxy-nginx-apply", "/usr/bin/systemctl"}
    units = {command for command in exact if command.startswith("/usr/bin/systemctl")}
    assert units == {
        f"/usr/bin/systemctl {verb} roxy@{color}.service"
        for verb in ("start", "stop", "restart", "reload")
        for color in ("blue", "green")
    }
    text = SUDOERS.read_text()
    assert "NOPASSWD: ROXY_SWITCH, ROXY_NGINX, ROXY_UNITS" in text
    for forbidden in ("ALL=(ALL)", "/bin/sh", "/usr/bin/install", "/usr/sbin/nginx", " enable ", "!env_reset"):
        assert forbidden not in text


def test_every_sudo_call_of_deploy_sh_is_allowed(sandbox: DeploySandbox) -> None:
    """Run deploys (first, low memory with the reload fallback, rollback) and check each `sudo` call, mapped back to
    production paths, against the sudoers rules: deploy.sh never needs a command the rules do not allow."""
    exact, patterns = sudoers_rules()
    first = sandbox.make_commit("ONE")
    assert sandbox.run(first).returncode == 0
    sandbox.set_memory_mb(400)
    sandbox.flag("gunicornc-fail")
    second = sandbox.make_commit("TWO", nginx_extra="# changed\n")
    assert sandbox.run(second).returncode == 0
    assert sandbox.run(script=sandbox.opt / "deploy_rollback.sh").returncode == 0
    mapping = {
        str(sandbox.bin / "systemctl"): "/usr/bin/systemctl",
        str(sandbox.bin / "roxy-switch-color"): "/usr/local/sbin/roxy-switch-color",
        str(sandbox.bin / "roxy-nginx-apply"): "/usr/local/sbin/roxy-nginx-apply",
    }
    seen = []
    for call in sandbox.calls():
        if not call.startswith("sudo "):
            continue
        program, _, args = call.removeprefix("sudo ").partition(" ")
        command = f"{mapping[program]} {args}"
        seen.append(command)
        assert command in exact or any(p.fullmatch(command) for p in patterns), command
    assert any(" reload roxy@" in c for c in seen)
    assert any("roxy-nginx-apply" in c for c in seen)
