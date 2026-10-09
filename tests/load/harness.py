"""Command line of the load harness: run scenarios in a private network namespace and print a results table.

What this is
    `python -m load.harness [scenario ...] [--scale X] [--json PATH] [--keep] [--work DIR]`, run from the
    `tests/` directory of the repository (the scenarios are listed in `scenarios.SCENARIOS`; with no names every
    one runs, in the order of plan 19.4 followed by the replay). It prints the machine it ran on and one table
    per scenario, and with `--json` also writes every number to a file.

Why it exists
    Plan 19.4 wants results recorded with the hardware (docs/PERFORMANCE.md). One command that prints exactly the
    table the document copies keeps the two in step, and the JSON form is what test_replay_profile.py asserts on.

How it works
    1. Unless it already runs in one, the harness starts itself again under `unshare -rn`: a new user and network
       namespace that contains only a loopback interface (brought up here). gunicorn, the mock Roblox and the
       client processes all live inside it, so nothing they do can reach a real system (plan 19.12). Without
       unprivileged namespaces it stops with exit status 3 (on Ubuntu 24.04 the AppArmor switch
       `kernel.apparmor_restrict_unprivileged_userns` must be 0).
    2. A temporary work directory holds the fake credentials and one state directory per scenario (removed after
       the scenario unless `--keep`).
    3. Each scenario starts its own mock and gunicorn master, sends its traffic, stops gunicorn gracefully, and
       reads Roxy's own metrics. A scenario that fails to start is reported as failed; the others still run.

What to read next
    `scenarios.py`, then docs/PERFORMANCE.md.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from importlib import metadata
from pathlib import Path
from typing import Any, Final

NAMESPACE_ENV: Final = "ROXY_LOAD_NAMESPACE"
EXIT_NO_NAMESPACE: Final = 3
TESTS_DIR: Final = Path(__file__).resolve().parents[1]


def can_unshare() -> bool:
    try:
        result = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


PATH_OPTIONS: Final = ("--json", "--work")


def absolute_paths(argv: list[str]) -> list[str]:
    """`argv` with the values of the path options made absolute (the namespace run starts in `tests/`)."""
    out = list(argv)
    for index, value in enumerate(out):
        if value in PATH_OPTIONS and index + 1 < len(out):
            out[index + 1] = str(Path(out[index + 1]).resolve())
        for option in PATH_OPTIONS:
            if value.startswith(option + "="):
                out[index] = option + "=" + str(Path(value.split("=", 1)[1]).resolve())
    return out


def enter_namespace(argv: list[str]) -> None:
    """Re-run this command inside `unshare -rn` (never returns), or exit when namespaces are not available."""
    if not can_unshare():
        print("load harness: unprivileged user and network namespaces (unshare -rn) are not available", file=sys.stderr)
        sys.exit(EXIT_NO_NAMESPACE)
    argv = absolute_paths(argv)
    env = {**os.environ, NAMESPACE_ENV: "1", "PYTHONPATH": str(TESTS_DIR)}
    os.chdir(TESTS_DIR)
    os.execvpe("unshare", ["unshare", "-rn", sys.executable, "-m", "load.harness", *argv], env)


def loopback_up() -> None:
    """A fresh network namespace has its loopback interface down."""
    ip = shutil.which("ip") or "/usr/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)


def machine() -> dict[str, Any]:
    """The hardware and software the numbers were measured on (plan 6.7 asks for both)."""
    import psutil

    model = ""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        model = platform.processor()

    def version(name: str) -> str:
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            return "absent"

    load = os.getloadavg()
    return {
        "cpu": model,
        "logical_cpus": os.cpu_count(),
        "memory_gib": round(psutil.virtual_memory().total / 2**30, 1),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "packages": {name: version(name) for name in ("gunicorn", "uvicorn", "uvloop", "httptools", "httpx")},
        "load_average_at_start": [round(value, 2) for value in load],
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
    }


def table(rows: list[tuple[str, str, str]]) -> str:
    """A plain fixed-width table: metric, measured value, target or note."""
    header = ("metric", "measured", "target or note")
    widths = [max(len(str(row[i])) for row in [header, *rows]) for i in range(3)]
    line = "-+-".join("-" * width for width in widths)
    out = [" | ".join(str(cell).ljust(width) for cell, width in zip(header, widths, strict=True)), line]
    out += [" | ".join(str(cell).ljust(width) for cell, width in zip(row, widths, strict=True)) for row in rows]
    return "\n".join(text.rstrip() for text in out)


def parse(argv: list[str]) -> argparse.Namespace:
    from load.scenarios import SCENARIOS

    parser = argparse.ArgumentParser(prog="python -m load.harness", description="Roxy v2 load harness (plan 19.4)")
    parser.add_argument("scenarios", nargs="*", help=f"scenarios to run (default: all): {', '.join(SCENARIOS)}")
    parser.add_argument("--scale", type=float, default=1.0, help="multiply every duration (for example 0.25)")
    parser.add_argument("--workers", type=int, default=2, help="gunicorn workers (production: 2)")
    parser.add_argument("--json", type=Path, help="write every number to this file")
    parser.add_argument("--work", type=Path, help="work directory (default: a new temporary directory)")
    parser.add_argument("--keep", action="store_true", help="keep each scenario's state and logs")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--steady-rate", type=float, default=200.0, help="requests a second of `steady` (200)")
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="a setting for every scenario, on top of its own (a 'what if' run; the value is read as JSON)",
    )
    args = parser.parse_args(argv)
    unknown = [name for name in args.scenarios if name not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario {', '.join(unknown)}; choose from {', '.join(SCENARIOS)}")
    try:
        args.overrides = tuple(setting(text) for text in args.set)
    except ValueError as exc:
        parser.error(str(exc))
    return args


def setting(text: str) -> tuple[str, Any]:
    """`key=value` with the value read as JSON (`600`, `0.5`, `"hold"`), else kept as text."""
    from roxy.config.catalog import CATALOG

    key, sep, raw = text.partition("=")
    if not sep or key not in CATALOG:
        raise ValueError(f"--set wants KEY=VALUE with a catalog setting, not {text!r}")
    try:
        return key, json.loads(raw)
    except json.JSONDecodeError:
        return key, raw


def main(argv: list[str]) -> int:
    if os.environ.get(NAMESPACE_ENV) != "1":
        enter_namespace(argv)
    loopback_up()
    from load.fleet import fake_credentials
    from load.scenarios import SCENARIOS, NotReady, Options, ScenarioResult

    args = parse(argv)
    names = list(args.scenarios) or list(SCENARIOS)
    work = args.work or Path(tempfile.mkdtemp(prefix="roxy-load-"))
    work.mkdir(parents=True, exist_ok=True)
    credentials = fake_credentials(work / "credentials")
    opts = Options(
        work,
        credentials,
        workers=args.workers,
        scale=args.scale,
        seed=args.seed,
        keep=args.keep,
        steady_rate=args.steady_rate,
        overrides=args.overrides,
    )
    info = machine()
    print(f"Roxy load harness: {info['cpu']}, {info['logical_cpus']} logical CPUs, {info['memory_gib']} GiB")
    print(f"kernel {info['kernel']}, Python {info['python']}, {info['packages']}, load {info['load_average_at_start']}")
    print(f"work directory {work}\n", flush=True)
    report: dict[str, Any] = {"machine": info, "scenarios": {}}
    failed = 0
    for name in names:
        started = time.monotonic()
        try:
            result = SCENARIOS[name](opts)
        except NotReady as exc:
            result = ScenarioResult(name, name, ok=False, rows=[("start", "gunicorn did not become ready", "")])
            result.data = {"log_tail": str(exc)}
        except Exception as exc:
            result = ScenarioResult(name, name, ok=False, rows=[("error", f"{type(exc).__name__}: {exc}", "")])
            result.data = {"traceback": traceback.format_exc()}
        elapsed = round(time.monotonic() - started, 1)
        failed += 0 if result.ok else 1
        report["scenarios"][name] = {"title": result.title, "ok": result.ok, "seconds": elapsed, "rows": result.rows,
                                     "data": result.data}  # fmt: skip
        print(f"== {name}: {result.title} ({elapsed} s{'' if result.ok else ', FAILED'})")
        print(table(result.rows), end="\n\n", flush=True)
        if args.json is not None:
            args.json.write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    if not args.keep and args.work is None:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
