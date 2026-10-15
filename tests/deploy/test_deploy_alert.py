"""deploy/tools/alert_on_failure.py: the OnFailure alert (plan 17.1, 17.7; parity row 105).

What this is
    Tests of the alert script: redaction of journal lines, the alert_emails formats, the per-unit stamp-file rate
    limit with its suppressed count, the deploy failure mode, a non-zero exit when a channel fails, and an end to
    end run with the system Python against a local SMTP server and a local webhook (stub systemctl and journalctl
    print fake secrets that must not reach either channel).

Why it exists
    v1's alert mailed 60 raw journal lines, never rate limited (a crash loop on systemd 254 or later meant one email
    every 3 s), and exited 0 when sending failed (v1 notes, sections 9 and 10). Each of those is pinned here, and
    the subject `Roxy DOWN: <unit> failed on <host>` is kept byte for byte.

How it works
    Functions are called directly with a `Settings` that points into a temporary directory. The end to end test
    runs `/usr/bin/python3 -I alert_on_failure.py roxy@blue.service` like roxy-alert@.service does, with
    ROXY_ALERT_SMTP_SSL=0 so a tiny in-test SMTP server on 127.0.0.1 can read the message.

What to read next
    deploy/tools/alert_on_failure.py, deploy/systemd/roxy-alert@.service.
"""

from __future__ import annotations

import base64
import http.server
import json
import re
import socket
import socketserver
import subprocess
import threading
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from deploy_sandbox import DEPLOY, load_script, write_exec

pytestmark = [pytest.mark.deploy]

SCRIPT = DEPLOY / "tools" / "alert_on_failure.py"
FAKE_TOKEN = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you|_" + "AB" * 40


@pytest.fixture(scope="module")
def alert() -> ModuleType:
    return load_script(SCRIPT, "roxy_alert_for_tests")


def settings_for(alert: ModuleType, tmp_path: Path, **extra: Any) -> Any:
    creds = tmp_path / "creds"
    creds.mkdir(exist_ok=True)
    return alert.Settings(
        credentials_dir=creds,
        state_dir=tmp_path / "state",
        deploy_failure_file=tmp_path / "last_failure.json",
        hostname="testhost",
        **extra,
    )


# --------------------------------------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    ("text", "leak"),
    [
        (f"cookie value {FAKE_TOKEN} end", "AB" * 40),
        ("Cookie: .ROBLOSECURITY=abcdef123456; other=1", "abcdef123456"),
        ("set-cookie: session=s3cr3tvalue; HttpOnly", "s3cr3tvalue"),
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi"),
        ("rotator http://user:hunter22pass@gate.example.invalid:823 failed", "hunter22pass"),
        ("GET /games.roblox.com/v1/games?universeIds=1&apiKey=zzz HTTP/1.1", "apiKey=zzz"),
        ("password=correct-horse-battery", "correct-horse-battery"),
        ('{"token": "abcdefgh12345678"}', "abcdefgh12345678"),
        ("GET /admin/invalidate/k1ll5w1tchT0ken HTTP/1.1", "k1ll5w1tchT0ken"),
        ("opaque " + "Zx9" * 20, "Zx9" * 20),
        # Headers logged as JSON or as a Python dict: a quote sits between the name and the separator.
        ('{"authorization": "Bearer ' + "q" * 42 + '"}', "q" * 42),
        ("{'Authorization': 'Basic dXNlcjpodW50ZXIy'}", "dXNlcjpodW50ZXIy"),
        ('{"Proxy-Authorization": "Basic cHJveHk6cGFzcw=="}', "cHJveHk6cGFzcw"),
        ('{"cookie": "session=s3cr3tv4lu3; theme=dark"}', "s3cr3tv4lu3"),
        ('{"x-api-key": "k3yv4lu3abc"}', "k3yv4lu3abc"),
    ],
)
def test_redact_removes_secrets(alert: ModuleType, text: str, leak: str) -> None:
    assert leak not in alert.redact(text)


def test_redact_json_headers_keeps_the_rest_of_the_line(alert: ModuleType) -> None:
    text = '{"authorization": "Bearer abc.def.ghi", "status": 500, "path": "/games.roblox.com/v1/games"}'
    redacted = alert.redact(text)
    assert "abc.def.ghi" not in redacted
    assert '"status": 500' in redacted
    assert '"path": "/games.roblox.com/v1/games"' in redacted


def test_redact_keeps_useful_text(alert: ModuleType) -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    text = f"roxy@blue.service: Main process exited, code=exited, status=1/FAILURE (release {sha})"
    assert alert.redact(text) == text
    assert alert.redact("GET /games.roblox.com/v1/games/votes 200") == "GET /games.roblox.com/v1/games/votes 200"


def test_redact_known_secret_values(alert: ModuleType) -> None:
    assert "plainappsecret" not in alert.redact("login failed for plainappsecret", ["plainappsecret"])


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("to: owner@example.invalid\nfrom: alt@example.invalid\n", ("owner@example.invalid", "alt@example.invalid")),
        ("owner@example.invalid\nalt@example.invalid\n", ("owner@example.invalid", "alt@example.invalid")),  # v1
        ("owner@example.invalid", ("owner@example.invalid", "owner@example.invalid")),
        (
            "# comment\nFrom: alt@example.invalid\nTo: owner@example.invalid",
            ("owner@example.invalid", "alt@example.invalid"),
        ),
    ],
)
def test_parse_addresses(alert: ModuleType, text: str, expected: tuple[str, str]) -> None:
    assert alert.parse_addresses(text) == expected


# ------------------------------------------------------------------------------------- rate limit and exit


class Sent:
    def __init__(self) -> None:
        self.emails: list[Any] = []
        self.webhooks: list[Any] = []


@pytest.fixture
def fake_channels(alert: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Sent:
    sent = Sent()
    monkeypatch.setattr(alert, "send_email", lambda settings, a, **kw: sent.emails.append((a, kw)))
    monkeypatch.setattr(alert, "send_webhook", lambda url, a: sent.webhooks.append((url, a)))
    monkeypatch.setattr(alert, "run_text", lambda cmd: f"(output of {cmd[0]})")
    return sent


def write_creds(settings: Any, *, webhook: str = "") -> None:
    (settings.credentials_dir / "smtp_password").write_text("fake-app-password")
    (settings.credentials_dir / "alert_emails").write_text("to: owner@example.invalid\nfrom: alt@example.invalid\n")
    (settings.credentials_dir / "alert_webhook_url").write_text(webhook)


def test_one_alert_per_unit_per_ten_minutes(alert: ModuleType, tmp_path: Path, fake_channels: Sent) -> None:
    settings = settings_for(alert, tmp_path)
    write_creds(settings)
    assert alert.main(["roxy@blue.service"], settings=settings, now=1000.0) == 0
    assert alert.main(["roxy@blue.service"], settings=settings, now=1100.0) == 0  # suppressed
    assert alert.main(["roxy@blue.service"], settings=settings, now=1200.0) == 0  # suppressed
    assert alert.main(["roxy@green.service"], settings=settings, now=1200.0) == 0  # another unit: its own stamp
    assert len(fake_channels.emails) == 2
    assert alert.main(["roxy@blue.service"], settings=settings, now=1000.0 + 600) == 0
    assert len(fake_channels.emails) == 3
    last = fake_channels.emails[-1][0]
    assert "Suppressed since last alert: 2" in last.body
    assert last.subject == "Roxy DOWN: roxy@blue.service failed on testhost"  # v1 subject, kept exactly
    assert fake_channels.emails[-1][1] == {
        "to_addr": "owner@example.invalid",
        "from_addr": "alt@example.invalid",
        "password": "fake-app-password",
    }


def test_send_failure_exits_non_zero_and_retries_next_time(
    alert: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = settings_for(alert, tmp_path)
    write_creds(settings)
    monkeypatch.setattr(alert, "run_text", lambda cmd: "")

    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(alert, "send_email", broken)
    assert alert.main(["roxy@blue.service"], settings=settings, now=5000.0) == 1
    assert alert.load_stamp(settings, "roxy@blue.service")["last_sent"] == 0.0, "a failed send does not start the gap"


def test_webhook_failure_is_a_failure_too(alert: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = settings_for(alert, tmp_path)
    write_creds(settings, webhook="http://127.0.0.1:9/hook")
    monkeypatch.setattr(alert, "run_text", lambda cmd: "")
    monkeypatch.setattr(alert, "send_email", lambda *a, **k: None)

    def broken(url: str, a: Any) -> None:
        raise OSError("refused")

    monkeypatch.setattr(alert, "send_webhook", broken)
    assert alert.main(["roxy@blue.service"], settings=settings, now=1.0) == 1
    assert alert.load_stamp(settings, "roxy@blue.service")["last_sent"] == 1.0, "the email went out"


def test_missing_credentials_exit_2(alert: ModuleType, tmp_path: Path, fake_channels: Sent) -> None:
    settings = settings_for(alert, tmp_path)
    assert alert.main(["roxy@blue.service"], settings=settings, now=1.0) == 2
    assert fake_channels.emails == []


def test_deploy_failure_alert(alert: ModuleType, tmp_path: Path, fake_channels: Sent) -> None:
    settings = settings_for(alert, tmp_path)
    write_creds(settings)
    sha = "89abcdef0123456789abcdef0123456789abcdef"
    settings.deploy_failure_file.write_text(
        json.dumps(
            {
                "status": "failed",
                "sha": sha,
                "short": sha[:12],
                "step": 5,
                "error": f"Smoke test failed {FAKE_TOKEN}",
                "rollback": "nothing was switched; stopped roxy@green.service",
                "at": "2026-10-07T03:00:00Z",
            }
        )
    )
    assert alert.main(["deploy-failure"], settings=settings, now=1.0) == 0
    message = fake_channels.emails[0][0]
    assert message.subject == f"Roxy: deploy {sha[:12]} failed at step 5"
    assert "AB" * 40 not in message.body
    assert "stopped roxy@green.service" in message.body
    assert alert.main(["deploy-failure"], settings=settings, now=2.0) == 0
    assert len(fake_channels.emails) == 1, "the same failed sha alerts once per 10 minutes"


def test_script_is_standard_library_only() -> None:
    """It runs on /usr/bin/python3 so a broken release cannot silence it (plan 17.1)."""
    text = SCRIPT.read_text()
    assert text.startswith("#!/usr/bin/python3 -I\n")
    imported = set(re.findall(r"^(?:from|import) ([a-z_.]+)", text, re.MULTILINE))
    allowed = {
        "__future__",
        "json",
        "os",
        "re",
        "smtplib",
        "socket",
        "ssl",
        "subprocess",
        "sys",
        "time",
        "urllib.request",
        "collections.abc",
        "dataclasses",
        "email.message",
        "pathlib",
        "typing",
    }
    assert imported <= allowed, imported - allowed


# ---------------------------------------------------------------------------------------------- end to end


class SMTPHandler(socketserver.StreamRequestHandler):
    """Just enough SMTP for smtplib: EHLO with AUTH PLAIN, MAIL, RCPT, DATA, QUIT."""

    def handle(self) -> None:
        server: Any = self.server
        self.wfile.write(b"220 localhost test\r\n")
        data_mode = False
        lines: list[str] = []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if data_mode:
                if line == ".":
                    server.messages.append("\n".join(lines))
                    data_mode = False
                    self.wfile.write(b"250 queued\r\n")
                else:
                    lines.append(line)
                continue
            verb = line.split(" ", 1)[0].upper()
            if verb == "EHLO":
                self.wfile.write(b"250-localhost\r\n250 AUTH PLAIN\r\n")
            elif verb == "AUTH":
                server.auth.append(base64.b64decode(line.split()[-1]).split(b"\0"))
                self.wfile.write(b"235 ok\r\n")
            elif verb in {"MAIL", "RCPT"}:
                self.wfile.write(b"250 ok\r\n")
            elif verb == "DATA":
                data_mode = True
                self.wfile.write(b"354 go\r\n")
            elif verb == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.payloads.append(json.loads(body))  # type: ignore[attr-defined]
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        return


def serve(server: Any) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return thread


def test_end_to_end_with_system_python(tmp_path: Path) -> None:
    smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTPHandler)
    smtp.messages, smtp.auth = [], []  # type: ignore[attr-defined]
    hook = http.server.ThreadingHTTPServer(("127.0.0.1", 0), WebhookHandler)
    hook.payloads = []  # type: ignore[attr-defined]
    serve(smtp)
    serve(hook)
    try:
        creds = tmp_path / "creds"
        creds.mkdir()
        (creds / "smtp_password").write_text("fake-app-password-123")
        (creds / "alert_emails").write_text("to: owner@example.invalid\nfrom: alt@example.invalid\n")
        (creds / "alert_webhook_url").write_text(f"http://127.0.0.1:{hook.server_address[1]}/hook-fake-secret")
        bin_dir = tmp_path / "bin"
        write_exec(
            bin_dir / "systemctl",
            f"""
            #!/bin/bash
            if [ "$1" = show ]; then printf 'NRestarts=4\\nResult=exit-code\\nExecMainStatus=1\\n'; exit 0; fi
            echo "roxy@blue.service - Roxy (blue)  Active: failed"
            echo "Cookie: .ROBLOSECURITY={FAKE_TOKEN}"
        """,
        )
        write_exec(
            bin_dir / "journalctl",
            f"""
            #!/bin/bash
            echo "2026-10-07T03:00:00 roxy-blue[1]: request GET /users.roblox.com/v1/users/1?secret=abc 500"
            echo "2026-10-07T03:00:01 roxy-blue[1]: leaked {FAKE_TOKEN}"
            echo "2026-10-07T03:00:02 roxy-blue[1]: smtp login fake-app-password-123 rejected"
            echo "2026-10-07T03:00:03 roxy-blue[1]: Killed (out of memory)"
        """,
        )
        env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "CREDENTIALS_DIRECTORY": str(creds),
            "STATE_DIRECTORY": str(tmp_path / "state"),
            "ROXY_ALERT_SMTP_HOST": "127.0.0.1",
            "ROXY_ALERT_SMTP_PORT": str(smtp.server_address[1]),
            "ROXY_ALERT_SMTP_SSL": "0",
        }
        result = subprocess.run(
            ["/usr/bin/python3", "-I", str(SCRIPT), "roxy@blue.service"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert len(smtp.messages) == 1  # type: ignore[attr-defined]
        message = smtp.messages[0]  # type: ignore[attr-defined]
        assert f"Subject: Roxy DOWN: roxy@blue.service failed on {socket.gethostname()}" in message
        assert "To: owner@example.invalid" in message
        assert "From: alt@example.invalid" in message
        assert "Killed (out of memory)" in message
        assert "Restarts so far: 4" in message
        for secret in ("AB" * 40, "secret=abc", "fake-app-password-123", "hook-fake-secret"):
            assert secret not in message
        assert smtp.auth[0][1:] == [b"alt@example.invalid", b"fake-app-password-123"]  # type: ignore[attr-defined]
        payload = hook.payloads[0]  # type: ignore[attr-defined]
        assert payload["subject"].startswith("Roxy DOWN: roxy@blue.service failed on")
        assert "AB" * 40 not in json.dumps(payload)
        again = subprocess.run(
            ["/usr/bin/python3", "-I", str(SCRIPT), "roxy@blue.service"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert again.returncode == 0
        assert "suppressed" in again.stdout
        assert len(smtp.messages) == 1  # type: ignore[attr-defined]
    finally:
        smtp.shutdown()
        hook.shutdown()
        smtp.server_close()
        hook.server_close()


def test_end_to_end_send_failure_is_non_zero(tmp_path: Path) -> None:
    with socket.socket() as probe:  # a port with nothing listening
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "smtp_password").write_text("x" * 16)
    (creds / "alert_emails").write_text("owner@example.invalid\n")
    (creds / "alert_webhook_url").write_text("")
    env = {
        "PATH": "/usr/bin:/bin",
        "CREDENTIALS_DIRECTORY": str(creds),
        "STATE_DIRECTORY": str(tmp_path / "s"),
        "ROXY_ALERT_SMTP_HOST": "127.0.0.1",
        "ROXY_ALERT_SMTP_PORT": str(port),
        "ROXY_ALERT_SMTP_SSL": "0",
    }
    result = subprocess.run(
        ["/usr/bin/python3", "-I", str(SCRIPT), "roxy@blue.service"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1, "v1 exited 0 here, hiding the failure"
    assert "email:" in result.stderr
