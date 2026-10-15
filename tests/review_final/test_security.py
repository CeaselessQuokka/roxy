"""Final review, security lens (plan 9): admin sign-in, the D5 bootstrap, argon2 limits, deploy privilege, backups.

What this is
    One reproduction per finding of `.remake/final_review/find_security.md` (ids `sec-1` to `sec-8`, most severe
    first). Each was a strict xfail until the final review fixed its finding; each is a regression test now, and
    none weakens an existing assertion.

Why it exists
    The final review before the owner signs off (HANDOFF.md): look for what would hurt in production. The findings
    are a path from the deploy user to root, a login burst that pushes a color past its memory ceiling, the
    one-time email bootstrap still working after enrollment, the allowlist and trusted-device exemption failing
    during a login flood, off-box backups leaving the box unencrypted, a hashing bound the first hashes of a worker
    skip, and two smaller items (smoke checks that vanish under `python -O`, the static location's missing
    Cross-Origin-Resource-Policy). The auth test helpers shipping in the package is ops-8
    (tests/review_final/test_ops.py), not repeated here.

How it works
    The auth tests use the shared auth harness (`auth_harness`, `tests/auth_harness.py`, out of the
    shipped package since ops-8) with the fixtures of tests/conftest.py (`env`,
    `fake_clock`, `credentials_dir`). The deploy tests run `deploy/install-system.sh --prefix`,
    `deploy/tools/backup.sh` and `scripts/smoke_remote.py` in subprocesses against temporary trees, stubs and
    loopback servers, as tests/deploy does. The memory test measures a real argon2 burst with the production
    parameters in a child process.

What to read next
    `.remake/final_review/find_security.md`, `src/roxy/admin/auth/flow.py`, `src/roxy/admin/auth/passwords.py`,
    `deploy/install-system.sh`, `deploy/tools/backup.sh`.
"""

from __future__ import annotations

import asyncio
import http.server
import importlib
import json
import os
import re
import shutil
import socketserver
import sqlite3
import stat
import subprocess
import sys
import threading
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from roxy.admin.auth import totp

REPO = Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy"
AUTH = "/admin/api/v1/auth"
ATTACKER_IP = "198.51.100.77"
OWNER_IP = "203.0.113.5"
OWNER_NETWORK = "203.0.113.0/24"


def auth_testing() -> ModuleType:
    """The shared auth test helpers, `tests/auth_harness.py` (out of the shipped package since finding ops-8; the root
    conftest puts tests/ on `sys.path`)."""
    return importlib.import_module("auth_harness")


@pytest.fixture
async def harness(env: Any, fake_clock: Any, credentials_dir: Path) -> AsyncIterator[Any]:
    async with auth_testing().auth_harness(env, clock=fake_clock, credentials_dir=credentials_dir) as running:
        yield running


def _bootstrap_pending(harness: Any, user_id: int) -> int:
    row = harness.ctx.dbs.control.read_sync(
        lambda conn: conn.execute("SELECT mfa_bootstrap_pending FROM admin_users WHERE id = ?", (user_id,)).fetchone()
    )
    return int(row[0])


def _stored_totp(harness: Any, user_id: int) -> bytes:
    row = harness.ctx.dbs.control.read_sync(
        lambda conn: conn.execute("SELECT totp_secret_enc FROM admin_users WHERE id = ?", (user_id,)).fetchone()
    )
    return bytes(row[0])


def _tool(name: str) -> str | None:
    """A binary from PATH or the no-root unpack location tests/deploy uses in WSL (`~/.local/p13tools`)."""
    found = shutil.which(name)
    if found:
        return found
    candidate = Path.home() / ".local" / "p13tools" / "usr" / "bin" / name
    return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None


# ======================================================================================= sec-1: deploy user to root


@pytest.mark.skipif(sys.platform == "win32", reason="the install script runs on Linux")
def test_install_system_never_changes_a_directory_swapped_for_a_link_after_its_check(tmp_path: Path) -> None:
    """Plan 9.14: the deploy user must never gain a path to root. It owns /opt/roxy, so it can replace
    /opt/roxy/releases at any moment. `directory()` checks `[ -L ]`, then runs mkdir, chmod and (as root) chown by
    path, all of which follow a link planted after the check; `file()` installs /opt/roxy/deploy.sh and then chowns
    it by path the same way. A stub `chmod` stands in for the deploy user winning that race: it swaps the directory
    for a link at the last moment before the real chmod runs. The victim directory (think /etc/systemd/system) must
    keep its mode; today chmod 0755 lands on it, and on the server the same moment hands it to roxy-deploy with
    chown. A fix that never changes a mode or owner by path inside a deploy-owned tree never calls the stub."""
    prefix = tmp_path / "root"
    victim = tmp_path / "victim"
    victim.mkdir()
    victim.chmod(0o700)
    (prefix / "opt" / "roxy").mkdir(parents=True)
    releases = prefix / "opt" / "roxy" / "releases"
    real_chmod = shutil.which("chmod")
    assert real_chmod is not None
    stubs = tmp_path / "bin"
    stubs.mkdir()
    stub = stubs / "chmod"
    stub.write_text(
        "#!/bin/bash\n"
        "# The deploy user's move, timed after install-system.sh looked for a link: swap one in.\n"
        'for arg in "$@"; do\n'
        '  if [ "$arg" = "$ROXY_RACE_PATH" ] && [ -d "$arg" ] && [ ! -L "$arg" ]; then\n'
        '    mv "$arg" "$arg.moved" && ln -s "$ROXY_RACE_VICTIM" "$arg"\n'
        "  fi\n"
        "done\n"
        f'exec {real_chmod} "$@"\n',
        encoding="utf-8",
    )
    os.chmod(stub, 0o755)
    result = subprocess.run(
        ["bash", str(DEPLOY / "install-system.sh"), "--prefix", str(prefix)],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **os.environ,
            "PATH": f"{stubs}{os.pathsep}{os.environ.get('PATH', '')}",
            "ROXY_RACE_PATH": str(releases),
            "ROXY_RACE_VICTIM": str(victim),
        },
        check=False,
    )
    assert stat.S_IMODE(victim.stat().st_mode) == 0o700, (
        "install-system.sh changed the mode of the directory a link swapped in after its check pointed at "
        f"(exit {result.returncode}); as root its chown gives that directory to the deploy user"
    )


# ======================================================================================= sec-2: argon2 memory


_ARGON2_BURST = """
import asyncio, resource
from roxy.admin.auth.passwords import HASH_CONCURRENCY, MAX_QUEUED_HASHES, PasswordHasher

async def main():
    hasher = PasswordHasher()  # the production parameters (plan 9.5)
    base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    await asyncio.gather(
        *(hasher.verify(None, f"guess-{i}") for i in range(HASH_CONCURRENCY + MAX_QUEUED_HASHES)),
        return_exceptions=True,
    )
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print((peak - base) // 1024)

asyncio.run(main())
"""


def _unit_value(path: Path, key: str) -> str:
    values = [line.split("=", 1)[1].strip() for line in path.read_text().splitlines() if line.startswith(f"{key}=")]
    assert len(values) == 1, (key, values)
    return values[0]


def _number(pattern: str, path: Path) -> int:
    found = re.search(pattern, path.read_text(), re.M)
    assert found is not None, (pattern, path)
    return int(found[1])


@pytest.mark.skipif(sys.platform == "win32", reason="ru_maxrss in KiB is the Linux unit")
def test_a_login_burst_fits_the_memory_a_warm_color_has_left() -> None:
    """Plan 9.5 sized `CapacityLimiter(2)` of 64 MiB hashes per worker for the 2 GB plan; DESIGN.md section 0 cut
    every other memory figure for the 909 MB server but not this one. Unauthenticated logins (any username: an
    unknown one verifies against the dummy hash) keep both slots of every worker busy, so a color holds
    workers x 2 x 64 MiB on top of its working set. A warm color is about 405 MiB (docs/PERFORMANCE.md "Memory per
    color", tests/deploy/test_deploy_units.py WARM_COLOR_MIB) under `MemoryMax=500M`: the kernel OOM-kills a worker
    long before the burst fits. Measured here with the real parameters and the unit's allocator lines."""
    unit = DEPLOY / "systemd" / "roxy@.service"
    memory_max = int(_unit_value(unit, "MemoryMax").removesuffix("M"))
    warm = _number(r"^WARM_COLOR_MIB = (\d+)", REPO / "tests" / "deploy" / "test_deploy_units.py")
    workers = _number(r"^ROXY_WORKERS=(\d+)", DEPLOY / "env" / "roxy.env.example")
    environment = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    for line in unit.read_text().splitlines():
        if line.startswith("Environment=MALLOC_"):
            name, value = line.removeprefix("Environment=").split("=", 1)
            environment[name] = value
    burst = subprocess.run(
        [sys.executable, "-c", _ARGON2_BURST], capture_output=True, text=True, timeout=120, env=environment, check=True
    )
    per_worker_mib = int(burst.stdout.strip().splitlines()[-1])
    headroom = memory_max - warm
    assert per_worker_mib * workers <= headroom, (
        f"one worker's login burst adds {per_worker_mib} MiB; {workers} workers add {per_worker_mib * workers} MiB "
        f"to a warm color of {warm} MiB under MemoryMax={memory_max}M (headroom {headroom} MiB)"
    )


# ======================================================================================= sec-3: the D5 bootstrap


async def test_the_email_bootstrap_closes_for_good_when_the_authenticator_is_enrolled(harness: Any) -> None:
    """D5 (DESIGN.md section 0, plan 9.5): the emailed code is a ONE-TIME first-login path, `mfa_bootstrap_pending`
    clears at enrollment, and replacing the authenticator needs a fresh second factor (plan 9.6). `mfa()` trusts
    the `bootstrap` flag stored in a login transaction and `_require_enroll_rights` trusts a session's `bootstrap`
    level; neither looks at the account again. So a bootstrap login started before the owner enrolled (its
    transaction lives `challenge_expiration`, and each resend extends it) finishes after enrollment, yields a
    bootstrap session, and that session enrolls a new authenticator over the owner's: the owner's codes stop
    working and their recovery codes are replaced. A second bootstrap session opened before enrollment does the
    same."""
    admin = harness.admin(with_totp=False, bootstrap=True, email="owner@example.invalid")
    attacker = harness.new_client()
    early = await harness.password_step(admin, client=attacker, ip=ATTACKER_IP)
    assert early.status_code == 200, early.text
    early_tx = early.json()["Transaction"]
    early_code = harness.mail.bodies("Admin 2FA")[-1].strip()

    second_browser = harness.new_client()
    second = await harness.password_step(admin, client=second_browser)
    second_code = harness.mail.bodies("Admin 2FA")[-1].strip()
    opened = await harness.mfa(second.json()["Transaction"], "email", code=second_code, client=second_browser)
    assert opened.json()["MfaLevel"] == "bootstrap"

    owner = await harness.password_step(admin)
    owner_code = harness.mail.bodies("Admin 2FA")[-1].strip()
    assert (await harness.mfa(owner.json()["Transaction"], "email", code=owner_code)).status_code == 200
    secret = (await harness.post(f"{AUTH}/totp/enroll/start")).json()["Secret"]
    harness.clock.advance(totp.TOTP_STEP_S)
    enrolled = await harness.post(f"{AUTH}/totp/enroll/confirm", {"code": totp.code_at(secret, harness.clock.now())})
    assert enrolled.status_code == 200, enrolled.text
    assert _bootstrap_pending(harness, admin.id) == 0
    stored = _stored_totp(harness, admin.id)

    late = await harness.mfa(early_tx, "email", code=early_code, client=attacker, ip=ATTACKER_IP)
    session = await second_browser.get(f"{AUTH}/session", headers=harness.headers())
    leftover_status = session.status_code
    if session.status_code == 200:
        token = session.json()["CsrfToken"]
        leftover = await second_browser.post(f"{AUTH}/totp/enroll/start", json={}, headers=harness.headers(csrf=token))
        leftover_status = leftover.status_code
    assert late.status_code != 200, f"the emailed code still signs in after enrollment: {late.status_code} {late.text}"
    assert "set-cookie" not in late.headers
    assert leftover_status != 200, "a bootstrap session from before enrollment may still replace the authenticator"
    assert _stored_totp(harness, admin.id) == stored


# ======================================================================================= sec-4: owner during a flood


async def test_an_exempt_owner_signs_in_while_slowed_guesses_fill_the_hash_queue(harness: Any) -> None:
    """Plan 9.5: the global guard "stops distributed guessing without letting an attacker lock the owner out ...
    IPs with a valid trusted-device token or in the admin allowlist (D6) are exempt from both the delay and the
    global count". The delay is spent while counted as pending (`passwords.py`), so a few slowed guesses from other
    networks fill the worker's `HASH_CONCURRENCY + MAX_QUEUED_HASHES` slots for the whole delay, and the exempt
    owner's own attempt meets `HashQueueFull`: 429 "Too many attempts". Two addresses keep a worker full."""
    admin = harness.admin()
    await harness.allow_admin_cidr(OWNER_NETWORK)
    await harness.set_settings(admin_login_global_max_per_min=1, admin_login_global_delay_s=4)
    guesses = [
        asyncio.create_task(
            harness.password_step(
                admin, client=harness.new_client(), ip=f"198.51.{100 + n}.9", password=f"wrong guess number {n}"
            )
        )
        for n in range(10)
    ]
    full = harness.hasher.capacity + harness.hasher.max_queued
    for _ in range(500):
        if harness.hasher.pending >= full:
            break
        await asyncio.sleep(0.01)
    assert harness.hasher.pending >= full, "the slowed guesses did not fill the queue"
    owner = await harness.password_step(admin, ip=OWNER_IP)
    await asyncio.gather(*guesses)
    assert owner.status_code == 200, f"the allowlisted owner was refused: {owner.status_code} {owner.text}"
    assert owner.json()["TwoFA"] is True


# ======================================================================================= sec-5: off-box backups


@pytest.fixture
def state_with_databases(tmp_path: Path) -> Path:
    from roxy.storage.migrate import migrate_paths

    directory = tmp_path / "state"
    directory.mkdir()
    migrate_paths({name: directory / f"{name}.db" for name in ("control", "hot", "metrics", "cache")})
    conn = sqlite3.connect(directory / "control.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    return directory


@pytest.mark.skipif(sys.platform == "win32", reason="the backup runs on Linux")
def test_an_off_box_copy_never_leaves_unencrypted(tmp_path: Path, state_with_databases: Path) -> None:
    """Plan D15: "Off-box copy optional (`ROXY_BACKUP_REMOTE` ...), encrypted with `age`". The set holds control.db
    (admin password hashes, encrypted TOTP secrets and credential, session and device hashes) and metrics.db (raw
    client addresses); plan 9.8 counts on the keys being the only thing a stolen copy lacks, and a bucket at a
    third party is where a copy gets stolen. backup.sh encrypts only when the recipients file exists and pushes
    whatever it made, so an owner who sets the remote first gets plaintext databases in the bucket, silently."""
    zstd = _tool("zstd")
    if zstd is None:
        pytest.skip("zstd is not installed (tests/deploy uses ~/.local/p13tools)")
    log = tmp_path / "rclone.log"
    rclone = tmp_path / "bin" / "rclone"
    rclone.parent.mkdir()
    rclone.write_text(f'#!/bin/bash\necho "$*" >>{log}\n', encoding="utf-8")
    os.chmod(rclone, 0o755)
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "rclone_config").write_text("[offsite]\ntype = local\n", encoding="utf-8")
    result = subprocess.run(
        ["bash", str(DEPLOY / "tools" / "backup.sh")],
        env={
            "PATH": f"{Path(zstd).parent}:/usr/bin:/bin",
            "ROXY_STATE_DIR": str(state_with_databases),
            "ROXY_BACKUP_DIR": str(tmp_path / "backups"),
            "ROXY_BACKUP_STATUS": str(tmp_path / "status" / "backup.json"),
            "ROXY_ZSTD": zstd,
            "ROXY_BACKUP_AGE_RECIPIENTS": str(tmp_path / "no-recipients"),
            "ROXY_BACKUP_DATE": "2026-10-07",
            "ROXY_DEPLOYED_VERSION_FILE": str(tmp_path / "no-deploy-yet"),
            "ROXY_RCLONE": str(rclone),
            "ROXY_BACKUP_REMOTE": "offsite",
            "CREDENTIALS_DIRECTORY": str(creds),
        },
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    pushed = log.read_text() if log.exists() else ""
    unencrypted = sorted(p.name for p in (tmp_path / "backups" / "2026-10-07").glob("*.db.zst"))
    assert not (pushed and unencrypted), (
        f"rclone copied a set holding {unencrypted} unencrypted (exit {result.returncode}): {pushed.strip()}"
    )


# ======================================================================================= sec-6: the dummy hash


async def test_a_fresh_worker_hashes_the_dummy_once_and_refuses_beyond_the_queue() -> None:
    """Plan 9.5: "when 4 hashes are already queued in a worker further login attempts get the lockout-style 429
    immediately". `PasswordHasher.dummy_hash` runs before `run`'s bound and every caller that finds no dummy hash
    makes its own, so a burst of unknown-user logins at a fresh worker (every start, every `max_requests` recycle)
    queues one full argon2 hash (64 MiB, about 250 ms) per request on the limiter, and the requests then refused as
    `HashQueueFull` have already paid for theirs. A worker should make the dummy once."""
    from roxy.admin.auth.passwords import HashQueueFull, PasswordHasher

    hasher = PasswordHasher(auth_testing().FAST_PARAMS)
    real = hasher._argon2
    made: list[int] = []

    class Counting:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def hash(self, value: str) -> str:
            made.append(1)
            return str(real.hash(value))

    hasher._argon2 = Counting()  # type: ignore[assignment]
    results = await asyncio.gather(*(hasher.verify(None, f"guess-{n}") for n in range(40)), return_exceptions=True)
    refused = sum(1 for result in results if isinstance(result, HashQueueFull))
    assert refused > 0
    assert len(made) <= 1, f"{len(made)} dummy hashes for one burst; {refused} of those callers were then refused"


# ======================================================================================= sec-7: smoke under -O


class _Handler(http.server.BaseHTTPRequestHandler):
    internal = False

    def do_GET(self) -> None:
        if self.internal:
            body = json.dumps({"Version": "0" * 40, "Color": "green"}).encode()
            status = 200
        else:
            body, status = b'"Internal Server Error"\n', 500
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return


class _Internal(_Handler):
    internal = True


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self) -> Any:
        request, _ = super().get_request()
        return request, ("local", 0)


@pytest.fixture
def broken_color(tmp_path: Path) -> Iterator[tuple[str, str]]:
    """A color whose every public page answers 500 (the internal socket answers its version)."""
    tcp = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    sock = tmp_path / "internal.sock"
    uds = _UnixServer(str(sock), _Internal)
    for server in (tcp, uds):
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        yield f"127.0.0.1:{tcp.server_address[1]}", str(sock)
    finally:
        for server in (tcp, uds):
            server.shutdown()
            server.server_close()


@pytest.mark.skipif(sys.platform == "win32", reason="the smoke test runs on the Linux server")
def test_the_smoke_gate_still_fails_a_broken_color_under_python_optimize(
    tmp_path: Path, broken_color: tuple[str, str]
) -> None:
    """Plan 17.4 step 5: the smoke test is the last gate before nginx switches; a check that always passes is worse
    than none (tests/deploy/test_deploy_smoke_remote.py). Every check in `scripts/smoke_remote.py` is an `assert`
    (bandit B101, the one low finding with an effect): with `-O` or `PYTHONOPTIMIZE` set in the deploy shell, a
    color answering 500 to `/`, `/health` and `/admin` passes all of them and deploy.sh switches traffic to it."""
    bind, sock = broken_color
    plain = [
        str(REPO / "scripts" / "smoke_remote.py"),
        "--color",
        "green",
        "--bind",
        bind,
        "--socket",
        sock,
        "--skip-proxy",
        "--env-dir",
        str(tmp_path),
        "--site-origin",
        "https://roxy.example.test",
    ]
    normal = subprocess.run([sys.executable, *plain], capture_output=True, text=True, timeout=120, check=False)
    assert normal.returncode == 1, normal.stdout + normal.stderr
    optimized = subprocess.run([sys.executable, "-O", *plain], capture_output=True, text=True, timeout=120, check=False)
    assert optimized.returncode == 1, "under -O the smoke gate passed a color that answers 500:\n" + optimized.stdout


# ======================================================================================= sec-8: static headers


def test_the_static_location_sends_cross_origin_resource_policy() -> None:
    """Plan 9.3: `Cross-Origin-Resource-Policy: same-origin` on admin and static responses. The app sends it on
    every page and on the static files it serves itself (`core/security_headers.py`), but in production nginx
    serves `/static/` straight from the release (plan 17.2) with only nosniff, Cache-Control and HSTS, so the
    admin's scripts and styles are embeddable cross-site there and differ from what the app answers."""
    template = (DEPLOY / "nginx" / "roxy.conf.template").read_text()
    block = template.split("location ^~ /static/ {", 1)[1].split("\n    }\n", 1)[0]
    assert re.search(r'add_header\s+Cross-Origin-Resource-Policy\s+"?same-origin"?', block, re.I), block
