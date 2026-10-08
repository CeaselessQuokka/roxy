"""Helpers for the deploy tests: a sandbox server for deploy.sh, tool discovery, and loaders for the root scripts.

What this is
    `DeploySandbox` builds a fake server layout in a temporary directory (/opt/roxy, /etc/roxy, /etc/nginx,
    /var/lib/roxy-deploy, /run/roxy-<color>, a bare git "GitHub" repository) and stub programs for everything
    deploy.sh touches outside itself: `sudo`, `systemctl`, `curl`, `uv`, the two root wrappers, and the release's
    `.venv/bin/python` and `gunicornc`. It then runs the REAL deploy/deploy.sh against that layout. Also here:
    `find_tool()` for optional binaries (nginx, shellcheck, zstd, age) and `load_script()` for Python files without
    a .py name (the root wrappers).

Why it exists
    Plan 19.9: the deploy must be tested like v1's tests/deploy_test.sh did, in a sandbox, with stubbed systemctl,
    nginx and sudo, so every failure path (failed build, failed health gate, failed migration, a concurrent deploy,
    rollback, first deploy, bootstrap, low-memory mode) is exercised without a server. Nothing here talks to the
    network: the git remote is a local bare repository, and the stubs answer from files.

How it works
    Stubs are small bash scripts that log every call to `state/calls.log` and keep their state in files:
    `state/units/<color>` exists while a color "runs", `.release` records which release it started on, `.workers`
    how many workers it has. Scenario flags are files in `state/flags/` (`fail-start-green`, `unhealthy-blue`,
    `smoke-fail`, ...), so a test sets up a failure by touching a file. deploy.sh reads every path from ROXY_*
    variables, which `run()` points into the sandbox, with short timeouts so the whole suite runs in seconds.

What to read next
    `tests/deploy/test_deploy_sh.py` (the scenarios), then `deploy/deploy.sh`.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy"


# ------------------------------------------------------------------------------------------------- tools


def find_tool(name: str) -> str | None:
    """An optional binary: $ROXY_TEST_<NAME>, then PATH, then the no-root unpack locations used in WSL."""
    override = os.environ.get(f"ROXY_TEST_{name.upper().replace('-', '_')}")
    if override and Path(override).is_file():
        return override
    found = shutil.which(name)
    if found:
        return found
    home = Path.home()
    for candidate in (
        home / ".local" / "nginxroot" / "usr" / "sbin" / name,
        home / ".local" / "p13tools" / "usr" / "bin" / name,
        home / ".local" / "bin" / name,
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def load_script(path: Path, name: str | None = None) -> ModuleType:
    """Import a Python script by path, even without a .py name (the root wrappers)."""
    module_name = name or "roxy_test_" + path.name.replace("-", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_loader(module_name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module  # dataclasses look their module up here
    loader.exec_module(module)
    return module


def write_exec(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    path.chmod(0o755)
    return path


# -------------------------------------------------------------------------------------------- the stubs

SUDO = r"""
#!/bin/bash
# sudo stub: record and run the command as the same user.
echo "sudo $*" >>"$ROXY_TEST_STATE/calls.log"
exec "$@"
"""

SYSTEMCTL = r"""
#!/bin/bash
# systemctl stub for roxy@blue.service and roxy@green.service.
S="$ROXY_TEST_STATE"
echo "systemctl $*" >>"$S/calls.log"
args=()
for a in "$@"; do [ "$a" = --quiet ] || args+=("$a"); done
verb="${args[0]:-}"
unit="${args[1]:-}"
color="${unit#roxy@}"
color="${color%.service}"
mkdir -p "$S/units"
case "$verb" in
  is-active)
    [ -e "$S/units/$color" ] && exit 0
    exit 3
    ;;
  start|restart)
    if [ -e "$S/flags/fail-start-$color" ] || [ -e "$S/flags/fail-migrate" ]; then
      rm -f "$S/units/$color"
      echo "Job for $unit failed because the control process exited with error code." >&2
      exit 1
    fi
    release="$(readlink "$ROXY_ROOT/releases/current-$color" 2>/dev/null || true)"
    basename "${release:-none}" >"$S/units/$color.release"
    marker="$ROXY_DEPLOY_STATE_DIR/start-workers-$color"
    if [ -e "$marker" ]; then cat "$marker" >"$S/units/$color.workers"; else echo 2 >"$S/units/$color.workers"; fi
    cp "$S/units/$color.workers" "$S/units/$color.start_workers"
    touch "$S/units/$color"
    ;;
  stop)
    [ -e "$S/flags/stop-hangs-$color" ] || rm -f "$S/units/$color"
    ;;
  reload)
    [ -e "$S/units/$color" ] || exit 1
    echo 2 >"$S/units/$color.workers"
    ;;
  *) ;;
esac
exit 0
"""

CURL = r"""
#!/bin/bash
# curl stub: the internal sockets of both colors, and the public /health through nginx.
S="$ROXY_TEST_STATE"
echo "curl $*" >>"$S/calls.log"
sock=""; url=""; resolve=""; wfmt=""; out=""; failflag=0
while [ $# -gt 0 ]; do
  case "$1" in
    --unix-socket) sock="$2"; shift ;;
    --resolve) resolve="$2"; shift ;;
    -w) wfmt="$2"; shift ;;
    -o) out="$2"; shift ;;
    --max-time) shift ;;
    --fail|-f) failflag=1 ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
active_color() {
  case "$(basename "$(readlink "$ROXY_NGINX_DIR/roxy-active-upstream.conf" 2>/dev/null || echo none)")" in
    roxy-upstream-blue.conf) echo blue ;;
    roxy-upstream-green.conf) echo green ;;
  esac
}
healthy() {
  local c="$1"
  [ -e "$S/units/$c" ] || return 1
  [ -e "$S/flags/unhealthy-$c" ] && return 1
  if [ -e "$S/flags/unhealthy-after-switch-$c" ] && [ "$(active_color)" = "$c" ]; then return 1; fi
  return 0
}
if [ -n "$sock" ]; then
  color="$(basename "$(dirname "$sock")")"
  color="${color#roxy-}"
  [ -e "$S/units/$color" ] || { echo "curl: (7) Couldn't connect to server" >&2; exit 7; }
  version="$(cat "$S/units/$color.release")"
  [ -e "$S/flags/bad-version-$color" ] && version="0000000000000000000000000000000000000000"
  if healthy "$color"; then
    printf '{"Ready":true,"Started":true,"PersistenceOK":true,"Version":"%s","IsLeader":false}' "$version"
  else
    printf '{"Ready":false,"Started":true,"PersistenceOK":false,"Version":"%s","IsLeader":false}' "$version"
  fi
  exit 0
fi
if [ -n "$resolve" ]; then
  # The public /health through nginx: v2's body has a Degraded list; with the flag public-v1 another nginx site
  # (v1's, during the cutover) answers with v1's keys only.
  c="$(active_color)"
  if [ -n "$c" ] && healthy "$c" && [ ! -e "$S/flags/public-down" ]; then code=200; else code=502; fi
  if [ "$code" != 200 ]; then
    body="<html>502 Bad Gateway</html>"
  elif [ -e "$S/flags/public-v1" ]; then
    body='{"DataBytes":1,"DataLimitBytes":2,"Paused":false,"PersistenceOK":true,"Status":"ok"}'
  else
    body='{"DataBytes":1,"DataLimitBytes":2,"Degraded":[],"Paused":false,"PersistenceOK":true,"Status":"ok"}'
  fi
  if [ "$code" != 200 ] && [ "$failflag" = 1 ]; then
    echo "curl: (22) The requested URL returned error: $code" >&2
    exit 22
  fi
  if [ -n "$out" ]; then printf '%s' "$body" >"$out"; else printf '%s' "$body"; fi
  [ -n "$wfmt" ] && printf '%s' "$code"
  exit 0
fi
echo "curl stub: unexpected call" >&2
exit 2
"""

UV = r"""
#!/bin/bash
# uv stub: `python install` succeeds; `sync` builds a fake .venv with python and gunicornc stubs.
S="$ROXY_TEST_STATE"
echo "uv $* (cwd $(pwd))" >>"$S/calls.log"
case "$1" in
  python) exit 0 ;;
  sync)
    if [ -e "$S/flags/fail-uv-sync" ]; then
      echo "error: Failed to build roxy (the lock file is broken)" >&2
      exit 1
    fi
    mkdir -p .venv/bin
    cp "$S/../bin/release-python" .venv/bin/python
    cp "$S/../bin/release-gunicornc" .venv/bin/gunicornc
    chmod +x .venv/bin/python .venv/bin/gunicornc
    exit 0
    ;;
esac
exit 0
"""

RELEASE_PYTHON = r"""
#!/bin/bash
# The release's .venv/bin/python stub: build_static and smoke_remote by name.
S="$ROXY_TEST_STATE"
echo "release-python $*" >>"$S/calls.log"
case "$1" in
  */build_static.py)
    out="$3"
    mkdir -p "$out/static"
    echo '{}' >"$out/static-manifest.json"
    exit 0
    ;;
  */smoke_remote.py)
    [ -e "$S/flags/smoke-fail" ] && { echo "FAIL  home  status 500"; exit 1; }
    case " $* " in
      *" --nginx "*) [ -e "$S/flags/smoke-nginx-fail" ] && { echo "FAIL  static  no HSTS"; exit 1; } ;;
    esac
    echo "smoke_remote: all checks passed"
    exit 0
    ;;
esac
exec /usr/bin/python3 "$@"
"""

RELEASE_GUNICORNC = r"""
#!/bin/bash
# gunicornc stub: `worker add N` and `show stats` against the stub unit state.
S="$ROXY_TEST_STATE"
echo "gunicornc $*" >>"$S/calls.log"
sock=""; cmd=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s) sock="$2"; shift ;;
    -c) cmd="$2"; shift ;;
  esac
  shift
done
color="$(basename "$(dirname "$sock")")"
color="${color#roxy-}"
[ -e "$S/flags/gunicornc-fail" ] && { echo "Error: cannot connect to $sock" >&2; exit 1; }
[ -e "$S/units/$color" ] || exit 1
workers="$(cat "$S/units/$color.workers")"
case "$cmd" in
  "worker add "*)
    n="${cmd#worker add }"
    echo $((workers + n)) >"$S/units/$color.workers"
    printf '{"added": %s}\n' "$n"
    ;;
  "show stats")
    printf '{"workers_current": %s, "workers_target": %s}\n' "$workers" "$workers"
    ;;
esac
exit 0
"""

SWITCH = r"""
#!/bin/bash
# roxy-switch-color stub: repoint the active upstream symlink.
S="$ROXY_TEST_STATE"
echo "roxy-switch-color $*" >>"$S/calls.log"
[ -e "$S/flags/switch-fail" ] && { echo "roxy-switch-color: nginx -t failed" >&2; exit 1; }
case "$1" in blue|green) ;; *) exit 2 ;; esac
ln -sfn "$ROXY_NGINX_DIR/roxy-upstream-$1.conf" "$ROXY_NGINX_DIR/roxy-active-upstream.conf"
echo "roxy-switch-color: nginx now sends traffic to $1"
"""

APPLY = r"""
#!/bin/bash
# roxy-nginx-apply stub: record the manifest hash like the real wrapper does. Flags: apply-fail (every apply
# fails), apply-fail-<sha> (only the apply of that commit fails).
S="$ROXY_TEST_STATE"
echo "roxy-nginx-apply $*" >>"$S/calls.log"
[ -e "$S/flags/apply-fail" ] && { echo "roxy-nginx-apply: nginx -t failed" >&2; exit 1; }
[ -e "$S/flags/apply-fail-$1" ] && { echo "roxy-nginx-apply: nginx -t failed for $1" >&2; exit 1; }
sha="$1"
if [ "${2:-}" = --initial-color ] && [ ! -L "$ROXY_NGINX_DIR/roxy-active-upstream.conf" ]; then
  ln -sfn "$ROXY_NGINX_DIR/roxy-upstream-$3.conf" "$ROXY_NGINX_DIR/roxy-active-upstream.conf"
fi
manifest="$ROXY_ROOT/releases/$sha/.roxy-nginx-manifest"
mkdir -p "$(dirname "$ROXY_NGINX_APPLIED")"
digest="$(sha256sum <"$manifest" | cut -d' ' -f1)"
printf '{"sha": "%s", "manifest_sha256": "%s"}\n' "$sha" "$digest" >"$ROXY_NGINX_APPLIED"
"""


# ------------------------------------------------------------------------------------------- the sandbox


def git(*args: str, cwd: Path, env: dict[str, str] | None = None) -> str:
    base = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    base.update(env or {})
    result = subprocess.run(["git", *args], cwd=cwd, env=base, capture_output=True, text=True, check=True)
    return result.stdout.strip()


class DeploySandbox:
    """A fake server for deploy.sh. See the module docstring."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.root = base / "root"
        self.bin = base / "bin"
        self.state = base / "state"
        self.home = base / "home"
        self.work = base / "work"
        self.remote = base / "gh" / "owner" / "roxy.git"
        self.opt = self.root / "opt" / "roxy"
        self.releases = self.opt / "releases"
        self.deploy_state = self.root / "var" / "lib" / "roxy-deploy"
        self.etc = self.root / "etc" / "roxy"
        self.nginx = self.root / "etc" / "nginx"
        self.applied = self.root / "var" / "lib" / "roxy-nginx-apply" / "applied.json"
        self.meminfo = self.root / "proc" / "meminfo"
        for directory in (
            self.bin,
            self.state / "flags",
            self.state / "units",
            self.home,
            self.releases,
            self.etc,
            self.nginx,
            self.meminfo.parent,
            self.root / "run" / "roxy-blue",
            self.root / "run" / "roxy-green",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        (self.state / "calls.log").touch()
        self.set_memory_mb(4000)
        for name, text in (
            ("sudo", SUDO),
            ("systemctl", SYSTEMCTL),
            ("curl", CURL),
            ("uv", UV),
            ("release-python", RELEASE_PYTHON),
            ("release-gunicornc", RELEASE_GUNICORNC),
            ("roxy-switch-color", SWITCH),
            ("roxy-nginx-apply", APPLY),
        ):
            write_exec(self.bin / name, text)
        self.write_env_files()
        for color in ("blue", "green"):
            shutil.copy(DEPLOY / "nginx" / f"roxy-upstream-{color}.conf", self.nginx / f"roxy-upstream-{color}.conf")
        self._init_remote()

    # --- setup helpers -----------------------------------------------------------------------------------

    def write_env_files(self, workers: int = 2) -> None:
        (self.etc / "roxy.env").write_text(
            f"ROXY_ENV=production\nROXY_WORKERS={workers}\nROXY_SITE_ORIGIN=https://roxy.example.test\n"
            "ROXY_DEPLOY_REPO_URL=https://github.com/OWNER/REPO.git\nROXY_DEPLOY_BRANCH=main\n",
            encoding="utf-8",
        )
        for color, port in (("blue", 8001), ("green", 8002)):
            (self.etc / f"{color}.env").write_text(
                f"ROXY_COLOR={color}\nROXY_BIND=127.0.0.1:{port}\n"
                f"ROXY_INTERNAL_SOCKET={self.root}/run/roxy-{color}/internal.sock\n",
                encoding="utf-8",
            )

    def set_memory_mb(self, available_mb: int) -> None:
        self.meminfo.write_text(
            f"MemTotal:         930000 kB\nMemFree:          100000 kB\nMemAvailable:   {available_mb * 1024} kB\n",
            encoding="utf-8",
        )

    def _init_remote(self) -> None:
        self.remote.parent.mkdir(parents=True, exist_ok=True)
        git("init", "--quiet", "--bare", "--initial-branch=main", str(self.remote), cwd=self.base)
        self.work.mkdir()
        git("init", "--quiet", "--initial-branch=main", cwd=self.work)

    def make_commit(
        self,
        marker: str,
        *,
        omit: tuple[str, ...] = (),
        deploy_sh_extra: str = "",
        nginx_extra: str = "",
        lock_extra: str = "",
        branch: str = "main",
    ) -> str:
        """Commit a minimal Roxy tree (the real deploy/ scripts) to `branch` of the remote; returns the sha."""
        work = self.work
        if branch != "main":
            git("checkout", "--quiet", "-B", branch, cwd=work)
        for entry in list(work.iterdir()):
            if entry.name != ".git":
                shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
        shutil.copytree(DEPLOY, work / "deploy", ignore=shutil.ignore_patterns("__pycache__"))
        (work / "deploy" / "deploy.sh").write_text(
            (DEPLOY / "deploy.sh").read_text(encoding="utf-8") + deploy_sh_extra, encoding="utf-8"
        )
        if nginx_extra:
            snippet = work / "deploy" / "nginx" / "snippets" / "roxy-security-headers.conf"
            snippet.write_text(snippet.read_text(encoding="utf-8") + nginx_extra, encoding="utf-8")
        (work / "scripts").mkdir()
        for name in ("smoke_remote.py", "build_static.py"):
            shutil.copy(REPO / "scripts" / name, work / "scripts" / name)
        (work / "src" / "roxy").mkdir(parents=True)
        (work / "src" / "roxy" / "__init__.py").write_text(f'MARKER = "{marker}"\n', encoding="utf-8")
        (work / "pyproject.toml").write_text('[project]\nname = "roxy"\nversion = "2.0.0"\n', encoding="utf-8")
        (work / "uv.lock").write_text(f"version = 1\n# {lock_extra}\n", encoding="utf-8")
        for path in omit:
            target = work / path
            shutil.rmtree(target) if target.is_dir() else target.unlink()
        git("add", "--all", cwd=work)
        git("commit", "--quiet", "-m", marker, cwd=work)
        sha = git("rev-parse", "HEAD", cwd=work)
        git("push", "--quiet", "--force", str(self.remote), f"HEAD:refs/heads/{branch}", cwd=work)
        if branch != "main":
            git("checkout", "--quiet", "main", cwd=work)
        return sha

    def install_deploy_script(self) -> Path:
        """Put the repository's deploy scripts where the workflow runs them (/opt/roxy)."""
        for name in ("deploy.sh", "deploy_rollback.sh"):
            shutil.copy(DEPLOY / name, self.opt / name)
            (self.opt / name).chmod(0o755)
        return self.opt / "deploy.sh"

    def flag(self, name: str) -> None:
        (self.state / "flags" / name).touch()

    def unflag(self, name: str) -> None:
        (self.state / "flags" / name).unlink(missing_ok=True)

    # --- running ------------------------------------------------------------------------------------------

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.home),
            "LANG": "C.UTF-8",
            "ROXY_TEST_STATE": str(self.state),
            "ROXY_ROOT": str(self.opt),
            "ROXY_DEPLOY_STATE_DIR": str(self.deploy_state),
            "ROXY_ETC_DIR": str(self.etc),
            "ROXY_NGINX_DIR": str(self.nginx),
            "ROXY_RUN_DIR_PREFIX": f"{self.root}/run/roxy-",
            "ROXY_NGINX_APPLIED": str(self.applied),
            "ROXY_SYSTEMCTL": str(self.bin / "systemctl"),
            "ROXY_NGINX_APPLY": str(self.bin / "roxy-nginx-apply"),
            "ROXY_SWITCH_COLOR": str(self.bin / "roxy-switch-color"),
            "ROXY_CURL": str(self.bin / "curl"),
            "ROXY_UV": str(self.bin / "uv"),
            "ROXY_PYTHON3": "/usr/bin/python3",
            "ROXY_DEPLOY_REPO_URL": str(self.remote),
            "ROXY_HEALTH_TIMEOUT_S": "2",
            "ROXY_POLL_INTERVAL_S": "0.1",
            "ROXY_WATCH_S": "1",
            "ROXY_WATCH_INTERVAL_S": "0.2",
            "ROXY_DRAIN_S": "0",
            "ROXY_STOP_TIMEOUT_S": "1",
            "ROXY_SCALE_TIMEOUT_S": "1",
            "ROXY_MEMINFO": str(self.meminfo),
            "UV_PYTHON_INSTALL_DIR": str(self.opt / "python"),
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        env.update(extra)
        return env

    def run(
        self, *args: str, script: Path | None = None, shell: str = "bash", timeout: float = 120, **extra: str
    ) -> subprocess.CompletedProcess[str]:
        script = script or self.opt / "deploy.sh"
        return subprocess.run(
            [shell, str(script), *args],
            env=self.env(**extra),
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    # --- inspection ---------------------------------------------------------------------------------------

    def active_color(self) -> str | None:
        link = self.nginx / "roxy-active-upstream.conf"
        if not link.is_symlink():
            return None
        return os.readlink(link).rsplit("roxy-upstream-", 1)[-1].removesuffix(".conf")

    def running(self, color: str) -> bool:
        return (self.state / "units" / color).exists()

    def unit_value(self, color: str, key: str) -> str:
        return (self.state / "units" / f"{color}.{key}").read_text(encoding="utf-8").strip()

    def current(self, color: str) -> str | None:
        link = self.releases / f"current-{color}"
        return Path(os.readlink(link)).name if link.is_symlink() else None

    def calls(self) -> list[str]:
        return (self.state / "calls.log").read_text(encoding="utf-8").splitlines()

    def clear_calls(self) -> None:
        (self.state / "calls.log").write_text("", encoding="utf-8")

    def release_dirs(self) -> list[str]:
        return sorted(
            p.name for p in self.releases.iterdir() if p.is_dir() and not p.is_symlink() and len(p.name) == 40
        )

    def manifest_hash(self, sha: str) -> str:
        return hashlib.sha256((self.releases / sha / ".roxy-nginx-manifest").read_bytes()).hexdigest()


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


# ------------------------------------------------------------------------------------------ nginx helpers

NGINX_TEST_HOST = "roxy.example.test"
HOME = Path.home()
HOST = NGINX_TEST_HOST


def nginx_binaries() -> list[tuple[str, str | None, Path, str]]:
    def candidate(env_name: str, root: str) -> tuple[str | None, Path, str]:
        explicit = os.environ.get(env_name)
        binary = Path(explicit) if explicit else HOME / ".local" / root / "usr" / "sbin" / "nginx"
        base = HOME / ".local" / root / "etc" / "nginx" / "nginx.conf"
        libs = f"{HOME}/.local/{root}/lib/x86_64-linux-gnu:{HOME}/.local/{root}/usr/lib/x86_64-linux-gnu"
        return (str(binary) if binary.is_file() else None, base, libs)

    found = []
    for label, env_name, root in (
        ("1.18", "ROXY_TEST_NGINX_118", "nginx118root"),
        ("1.24", "ROXY_TEST_NGINX", "nginxroot"),
        ("new", "ROXY_TEST_NGINX_NEW", "nginxnewroot"),
    ):
        binary, base, libs = candidate(env_name, root)
        if label == "1.24" and binary is None and shutil.which("nginx"):
            binary = shutil.which("nginx")
        found.append((label, binary, base, libs))
    return found


def ubuntu_nginx_conf(base: Path) -> str:
    """Ubuntu's own nginx.conf when unpacked next to the binary, else the same directives (24.04 defaults)."""
    if base.is_file():
        return base.read_text(encoding="utf-8")
    fallback = HOME / ".local" / "nginxroot" / "etc" / "nginx" / "nginx.conf"
    if fallback.is_file():
        return fallback.read_text(encoding="utf-8")
    return (
        "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\nerror_log /var/log/nginx/error.log;\n"
        "include /etc/nginx/modules-enabled/*.conf;\nevents {\n\tworker_connections 768;\n}\nhttp {\n"
        "\tsendfile on;\n\ttcp_nopush on;\n\ttypes_hash_max_size 2048;\n\tinclude /etc/nginx/mime.types;\n"
        "\tdefault_type application/octet-stream;\n\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n"
        "\tssl_prefer_server_ciphers on;\n\taccess_log /var/log/nginx/access.log;\n\tgzip on;\n"
        "\tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n"
    )


def build_prefix(prefix: Path, base_conf: str, *, namespaced: bool = False) -> None:
    """An /etc/nginx look-alike under `prefix`, with test certificates and private temp and log paths.

    Inside the user namespace nginx runs as (mapped) root and would chown its temp directories to its worker user,
    which does not exist in the namespace, so the worker user there is root itself."""
    import trustme

    for sub in ("logs", "tmp", "sites-enabled", "sites-available", "snippets", "conf.d", "modules-enabled", "releases"):
        (prefix / sub).mkdir(parents=True, exist_ok=True)
    mime = HOME / ".local" / "nginxroot" / "etc" / "nginx" / "mime.types"
    (prefix / "mime.types").write_text(
        mime.read_text() if mime.is_file() else "types {\n    text/html html;\n    text/css css;\n}\n"
    )
    ca = trustme.CA()
    cert = ca.issue_cert(HOST, f"www.{HOST}")
    cert_dir = prefix / "certs" / HOST
    cert_dir.mkdir(parents=True)
    cert.private_key_pem.write_to_path(str(cert_dir / "privkey.pem"))
    cert.cert_chain_pems[0].write_to_path(str(cert_dir / "fullchain.pem"))
    text = re.sub(r"^user .*;$", "", base_conf, flags=re.MULTILINE)
    text = text.replace("/run/nginx.pid", str(prefix / "nginx.pid"))
    text = text.replace("/var/log/nginx/", f"{prefix}/logs/").replace("/etc/nginx/", f"{prefix}/")
    temps = "".join(
        f"\t{name}_temp_path {prefix}/tmp/{name};\n" for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
    )
    text = text.replace("http {\n", "http {\n" + temps, 1)
    user = "user root root;\n" if namespaced else ""
    (prefix / "nginx.conf").write_text(f"{user}error_log {prefix}/logs/main-error.log;\n" + text)
    shutil.copy(DEPLOY / "nginx" / "snippets" / "roxy-security-headers.conf", prefix / "snippets")
    for color in ("blue", "green"):
        shutil.copy(DEPLOY / "nginx" / f"roxy-upstream-{color}.conf", prefix)
    os.symlink(prefix / "roxy-upstream-blue.conf", prefix / "roxy-active-upstream.conf")


def high_ports(text: str) -> str:
    """nginx -t binds the listen sockets; a normal user may not bind 80 or 443, so the test moves them."""
    text = re.sub(r"listen (\[::\]:)?80\b", lambda m: f"listen {m.group(1) or ''}18080", text)
    return re.sub(r"listen (\[::\]:)?443\b", lambda m: f"listen {m.group(1) or ''}18443", text)


def can_unshare() -> bool:
    """True when unprivileged user and network namespaces work (WSL; not on hosts that restrict them)."""
    unshare = shutil.which("unshare")
    if unshare is None:
        return False
    return subprocess.run([unshare, "-rn", "true"], capture_output=True, check=False).returncode == 0


def nginx_command(binary: str, prefix: Path, version: tuple[int, int, int], *, unshare: bool = False) -> list[str]:
    """`nginx -p <prefix> -c <conf>`; inside a private user and network namespace when possible, where the test
    may bind ports 80 and 443 like root without touching the host's network."""
    cmd = ["unshare", "-rn"] if unshare else []
    cmd += [binary, "-p", f"{prefix}/", "-c", str(prefix / "nginx.conf")]
    if version >= (1, 19, 5):
        cmd += ["-e", str(prefix / "logs" / "startup-error.log")]
    return cmd
