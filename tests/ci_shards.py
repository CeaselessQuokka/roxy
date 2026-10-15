"""Split one pytest run into N shards by test file, so a long suite runs as several CI jobs in parallel.

What this is
    The logic behind the `--shard K/N` option that tests/conftest.py registers: of the collected tests, keep only
    the files that belong to shard K of N and deselect the rest. `pytest tests/integration --shard 2/6` runs the
    second sixth of the integration suite.

Why it exists
    The integration suite takes about 50 minutes in one process on the dev machine, and longer on a GitHub-hosted
    runner, while a job there should stay well under its `timeout-minutes` (30); the unit job's suites take about
    25 minutes against a limit of 40. ci.yml therefore runs each as a matrix of jobs, one per shard. pytest-xdist
    is not a dependency, and a split by hand (lists of files in ci.yml) would silently miss the next new file;
    this split cannot.

How it works
    - A test file is the unit: its tests stay together, in their order, in one process, exactly as in a full run.
    - A file weighs as many distinct test functions as it has; the cases of one parametrized function count once,
      because they are usually cheap variations (tests/integration/pages/test_pages_core.py has 581 cases that run
      in less time than one page file of 30 tests). Weighed that way, the longest of 6 integration shards took
      about 1.2 times an even split of the measured time; weighed by cases, the shard holding that one file ran
      for 2 minutes while another ran for 11.
    - Files are taken heaviest first (then by path) and each goes to the shard that is lightest so far (ties: the
      lowest shard number), the usual greedy balance.
    - Every job computes the same split from the same collection, so the N shards together run every collected
      test exactly once, whatever files are added or removed.

What to read next
    tests/conftest.py (`pytest_addoption`, `pytest_collection_modifyitems`), the unit and integration jobs in
    .github/workflows/ci.yml, and tests/unit/test_ci_shards.py.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Sequence

SHARD_RE = re.compile(r"^\s*(?P<index>\d+)\s*/\s*(?P<count>\d+)\s*$")
"""What `--shard` accepts: `K/N` with 1 <= K <= N, for example `3/6`."""


def parse_shard(text: str) -> tuple[int, int]:
    """`"2/6"` -> `(2, 6)`; ValueError for anything that is not `K/N` with 1 <= K <= N."""
    match = SHARD_RE.match(text)
    if match is None:
        raise ValueError(f"--shard takes K/N (for example 2/6), not {text!r}")
    index, count = int(match.group("index")), int(match.group("count"))
    if not 1 <= index <= count:
        raise ValueError(f"--shard {text}: K must be between 1 and N")
    return index, count


def file_of(node_id: str) -> str:
    """`tests/a/test_b.py::test_c[x]` -> `tests/a/test_b.py`."""
    return node_id.split("::", 1)[0]


def file_weights(node_ids: Iterable[str]) -> dict[str, int]:
    """Each file's weight: its number of distinct test functions (the cases of a parametrized one count once)."""
    functions: dict[str, set[str]] = defaultdict(set)
    for node_id in node_ids:
        function = node_id.split("[", 1)[0]
        functions[file_of(function)].add(function)
    return {path: len(names) for path, names in functions.items()}


def assign_files(weights: dict[str, int], count: int) -> list[list[str]]:
    """The files of each shard (shard 1 first), each list sorted by path: heaviest file first onto the lightest
    shard so far."""
    shards: list[list[str]] = [[] for _ in range(count)]
    loads = [0] * count
    for path in sorted(weights, key=lambda name: (-weights[name], name)):
        lightest = loads.index(min(loads))
        shards[lightest].append(path)
        loads[lightest] += weights[path]
    return [sorted(files) for files in shards]


def split[T](items: Sequence[T], node_ids: Sequence[str], index: int, count: int) -> tuple[list[T], list[T]]:
    """(kept, deselected): the items whose file is in shard `index` of `count`, in their collected order.

    `node_ids` are the items' pytest node ids (relative to the rootdir), one per item, in the same order."""
    if len(node_ids) != len(items):
        raise ValueError("one node id per item")
    mine = set(assign_files(file_weights(node_ids), count)[index - 1])
    kept = [item for item, node_id in zip(items, node_ids, strict=True) if file_of(node_id) in mine]
    dropped = [item for item, node_id in zip(items, node_ids, strict=True) if file_of(node_id) not in mine]
    return kept, dropped
