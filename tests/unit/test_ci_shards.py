"""The `--shard K/N` split CI uses to run a long suite as parallel jobs (tests/ci_shards.py, tests/conftest.py).

What this is
    Tests of the shard arithmetic (parsing, the greedy balance, the split of collected items) and one end to end
    check: the shards of a real suite, collected by pytest with the option, together hold every test exactly once.

Why it exists
    ci.yml runs the unit job's suites and tests/integration as matrices of `--shard K/N` jobs (this file runs in
    one of those shards itself). A split that dropped a file, ran one twice or
    depended on the order of collection would make CI quietly test less than the suite, which is the failure the
    whole job split is there to avoid.

How it works
    Plain calls of the helper functions, then `python -m pytest --collect-only -q --shard K/3 tests/parity` in a
    child process for each K, compared with the same collection without the option.

What to read next
    tests/ci_shards.py, the unit and integration jobs in .github/workflows/ci.yml.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import ci_shards

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(("text", "expected"), [("1/1", (1, 1)), ("2/6", (2, 6)), (" 6 / 6 ", (6, 6))])
def test_parse_shard_accepts_k_of_n(text: str, expected: tuple[int, int]) -> None:
    assert ci_shards.parse_shard(text) == expected


@pytest.mark.parametrize("text", ["", "3", "0/4", "5/4", "1/0", "a/b", "1/4/2", "-1/4"])
def test_parse_shard_refuses_anything_else(text: str) -> None:
    with pytest.raises(ValueError, match="--shard"):
        ci_shards.parse_shard(text)


def test_every_file_lands_in_exactly_one_shard_and_the_loads_stay_close() -> None:
    weights = {f"tests/integration/test_{n:02d}.py": (n * 7) % 23 + 1 for n in range(40)}
    for count in (1, 2, 4, 6, 7):
        shards = ci_shards.assign_files(weights, count)
        assert len(shards) == count
        placed = [path for files in shards for path in files]
        assert sorted(placed) == sorted(weights), count
        loads = [sum(weights[path] for path in files) for files in shards]
        assert max(loads) - min(loads) <= max(weights.values()), (count, loads)
        assert shards == ci_shards.assign_files(dict(reversed(list(weights.items()))), count), "order independent"


def test_a_file_weighs_its_distinct_test_functions() -> None:
    node_ids = [
        "tests/a.py::test_one[1]",
        "tests/a.py::test_one[2]",
        "tests/a.py::test_one[3]",
        "tests/a.py::test_two",
        "tests/b.py::TestGroup::test_x",
        "tests/b.py::TestGroup::test_y[p::q]",
    ]
    assert ci_shards.file_weights(node_ids) == {"tests/a.py": 2, "tests/b.py": 2}


def test_split_keeps_collected_order_and_the_shards_partition_the_items() -> None:
    node_ids = [
        "b.py::test_1",
        "a.py::test_1",
        "b.py::test_2[x]",
        "c.py::test_1",
        "a.py::test_2",
        "d.py::test_1",
        "c.py::test_2",
        "b.py::test_2[y]",
    ]
    items = list(range(len(node_ids)))
    seen: list[int] = []
    for index in (1, 2, 3):
        kept, dropped = ci_shards.split(items, node_ids, index, 3)
        assert kept == sorted(kept), "collected order is kept"
        assert sorted(kept + dropped) == items
        files_kept = {ci_shards.file_of(node_ids[item]) for item in kept}
        assert not files_kept & {ci_shards.file_of(node_ids[item]) for item in dropped}, "a file is never split"
        seen.extend(kept)
    assert sorted(seen) == items


def collect(*extra: str) -> list[str]:
    command = [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *extra, "tests/parity"]
    done = subprocess.run(command, cwd=REPO, capture_output=True, text=True, timeout=300, check=False)
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    return [line for line in done.stdout.splitlines() if "::" in line]


def test_the_shard_option_splits_a_real_collection_without_loss_or_overlap() -> None:
    everything = collect()
    assert everything
    shards = [collect("--shard", f"{index}/3") for index in (1, 2, 3)]
    assert all(shards), "every shard has tests"
    combined = [test_id for shard in shards for test_id in shard]
    assert sorted(combined) == sorted(everything)
    assert len(combined) == len(set(combined))
