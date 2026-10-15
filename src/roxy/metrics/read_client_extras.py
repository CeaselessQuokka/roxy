"""Read models for what the Clients tables need beyond one client's own rows: peers, last seen and recorded scores.

What this is
    Functions over a metrics.db connection (run them inside `Database.read`):
      * `peer_counts(conn, client_type, keys, pieces)`: for each IP, the distinct places it called as; for each
        place, the distinct IPs it was called from (v1's "Places" and "IPs" columns of Top Talkers and Callers);
      * `peer_list(conn, client_type, key, pieces, limit)`: one client's peers with their numbers (the drill-down's
        "Source IPs" or "Places" list);
      * `attach_last_seen(conn, client_type, rows, pieces)`: the newest bucket with a request of each row's client;
      * `recorded_scores(conn, keys, since)`: the bot score each address was last recorded with, fleet-wide (the
        `client_score_hour` producer), for addresses the per-worker tracker has no live view of.
    `pieces` is the list of `(table, start, end)` the caller read the window from (`queries.client_table_sync`, or
    `read_clients.client_pieces`), so every number here covers exactly the rows the table itself counted.

Why it exists
    v1's Callers and Top Talkers showed on every row the last time a client was seen and its peer count, which is
    how the owner told one game's many servers (one place, many IPs) from one scraper cycling place ids (one IP, many
    places) (plan 14.1 row 9, parity row 73, finding parity-7). The `ip` and `place` rows are counted apart, so the
    recorder also keeps `pair` rows (`rollups.PAIR_CLIENT_TYPE`: one IP calling as one place). The Clients page also
    has a fleet-wide bot score source since the producers lane (lane_producers request 6): a score recorded by any
    worker in the last day answers when this worker saw no recent request.

How it works
    - Pair keys are `<ip>|<place>` (`rollups.pair_key`); IP keys never hold the separator, so a key splits at its
      first one. Counting distinct peers across levels is one SQL statement over the union of the pieces, so a peer
      seen in an hour row and again in a minute row counts once. The `other` row of each bucket is skipped.
    - For IP rows the pair rows are found by key range (`<ip>|` to `<ip>}`, the index on client_type and key, named
      with `INDEXED BY` so the planner statistics cannot trade it for a skip-scan, see `KEY_INDEX`); for place rows by
      the key's place part, an index range of `*_pair_place` (metrics migration 0009, a partial index on that
      expression; it was a scan of every pair row of the window, the Clients page's slowest read, plan 6.7).
    - Peer counts come from the pair rows the top-N caps kept (`max_ip_activity_records` per bucket): under a flood
      of pairs they are lower bounds, and `PEERS_BASIS` says so.
    - Everything is bounded: keys in chunks of `KEY_CHUNK`, lists to `MAX_PEERS`, scores to the keys asked for.

What to read next
    `roxy/metrics/queries.py` (`client_table_sync`), `roxy/metrics/read_clients.py` (one client's own rows),
    `roxy/metrics/producers.py` (`client_score_hour`), then `roxy/admin/api/clients.py`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from typing import Any, Final

from roxy.metrics.rollups import PAIR_CLIENT_TYPE, PAIR_SEPARATOR

OTHER_KEY: Final = "other"
"""The folded row of each bucket (`rollups` caps): never a client, so it has no peers."""
KEY_CHUNK: Final = 200
"""Keys per statement (SQLite's bound parameter limit is far above it)."""
WHOLE_WINDOW_CHUNKS: Final = 5
"""Above this many chunks of keys, `attach_last_seen` reads the whole window once instead."""
MAX_PEERS: Final = 100
"""Most peers one drill-down list returns."""
PEERS_BASIS: Final = (
    "distinct peers among the IP and place pairs kept per bucket (the busiest max_ip_activity_records); a lower bound "
    "when more pairs than that were active at once"
)
SCORE_BASIS: Final = "recorded: the largest score any worker computed in the client's latest scored hour"
_NEXT_SEPARATOR: Final = chr(ord(PAIR_SEPARATOR) + 1)
"""The character after the separator: `<ip>|` <= key < `<ip>}` is every pair key of one IP."""
KEY_INDEX: Final = "{table}_client"
"""The index an IP's pair rows are read through (`client_*_client`: type, key, time; metrics migration 0001).

It is named with `INDEXED BY` because the planner left it once the client tables had statistics. `PRAGMA optimize`
(on the writer's close and in the daily maintenance, plan 6.5) analyzes them, and `sqlite_stat1` then shows thousands
of pair rows per place on `*_pair_place` (9,136 at plan 6.6's volume), so SQLite skip-scans that index for an IP
(every place, then the window's time range: its rows come in place order, which `count(DISTINCT <place>)` likes)
instead of reading the IP's own key range. That reads every pair row of the window for each address: 25 ms an
address instead of 0.1 ms, 0.6 to 0.7 s for the 25 rows of Clients > IP addresses, 0.6 s for one address's peer list
and 6 s for an export page of 250 addresses (measured on the template of the 2026-10-14 quiet-machine run; the
2026-10-11 pass measured the card at 92 ms on a template whose 0009 indexes had no statistics yet). With the name the
plan no longer depends on what was analyzed, and a missing index fails the statement instead of scanning."""
ROW_COLUMNS: Final = "client_key, requests, refused, served, bucket_start"
"""What `_union` selects for a list of peers with their numbers (`peer_list`)."""
KEY_COLUMNS: Final = "client_key"
"""What `_union` selects for a count of peers (`peer_counts`): only the key, so every piece is read from its index
alone (a covering index; a UNION ALL of several levels is not flattened into the count, so each column it selects
that the index lacks is one more table lookup per pair row)."""


def _union(
    pieces: Sequence[tuple[str, int, int]],
    where: str,
    where_params: Sequence[Any],
    *,
    key_range: bool = False,
    columns: str = ROW_COLUMNS,
) -> tuple[str, list[Any]]:
    """`SELECT <columns>` (`ROW_COLUMNS` or `KEY_COLUMNS`) of the pair rows of every piece matching `where` (bound
    `where_params`), as one UNION ALL with its parameters in order. `key_range` says `where` is a range of pair keys
    (`_ip_ranges`), read through `KEY_INDEX`."""
    parts: list[str] = []
    params: list[Any] = []
    for table, lo, hi in pieces:
        source = f"{table} INDEXED BY {KEY_INDEX.format(table=table)}" if key_range else table
        # The pair type is written as a literal: it repeats the WHERE term of the `*_pair_place` partial indexes
        # (metrics migration 0009), which SQLite needs before it uses a partial index.
        parts.append(
            f"SELECT {columns} FROM {source} "  # noqa: S608 (client table names and the column constants above)
            f"WHERE client_type = '{PAIR_CLIENT_TYPE}' AND bucket_start >= ? AND bucket_start < ? AND client_key != ? "
            f"AND ({where})"
        )
        params.extend([int(lo), int(hi), OTHER_KEY, *where_params])
    return " UNION ALL ".join(parts), params


def _ip_ranges(keys: Sequence[str]) -> tuple[str, list[Any]]:
    clause = " OR ".join("(client_key >= ? AND client_key < ?)" for _ in keys)
    params: list[Any] = []
    for key in keys:
        params.extend([f"{key}{PAIR_SEPARATOR}", f"{key}{_NEXT_SEPARATOR}"])
    return clause, params


_IP_SQL: Final = f"substr(client_key, 1, instr(client_key, '{PAIR_SEPARATOR}') - 1)"
_PLACE_SQL: Final = f"substr(client_key, instr(client_key, '{PAIR_SEPARATOR}') + 1)"


def _sides(client_type: str) -> tuple[str, str]:
    """(the SQL of the client's own side of a pair key, the SQL of the peer's side)."""
    if client_type == "ip":
        return _IP_SQL, _PLACE_SQL
    if client_type == "place":
        return _PLACE_SQL, _IP_SQL
    raise ValueError("client_type must be 'ip' or 'place'")


def _matching(client_type: str, chunk: Sequence[str], own: str) -> tuple[str, list[Any]]:
    if client_type == "ip":
        return _ip_ranges(chunk)
    return f"{own} IN ({', '.join('?' for _ in chunk)})", list(chunk)


def peer_counts(
    conn: sqlite3.Connection, client_type: str, keys: Iterable[str], pieces: Sequence[tuple[str, int, int]]
) -> dict[str, int]:
    """`{key: distinct peers}` in the pieces for each of `keys` that has any (missing keys have none)."""
    own, peer = _sides(client_type)
    wanted = [key for key in dict.fromkeys(str(k) for k in keys) if key and key != OTHER_KEY]
    out: dict[str, int] = {}
    if not wanted or not pieces:
        return out
    if client_type == "ip":
        # One statement per address, each an indexed range (`client_minute_client` is ordered by type, key, time):
        # SQLite does not turn an OR of ranges into index seeks, so one statement with them all read every pair row
        # of the window (0.2 s for a page of 25 addresses at plan 6.6's volume; plan 6.7). The index is named
        # (`KEY_INDEX`): with statistics the planner skip-scanned `*_pair_place` instead, 0.6 s for the same page.
        for key in wanted:
            union, params = _union(pieces, *_ip_ranges([key]), key_range=True, columns=KEY_COLUMNS)
            row = conn.execute(f"SELECT count(DISTINCT {peer}) FROM ({union})", params).fetchone()  # noqa: S608
            if row is not None and row[0]:
                out[key] = int(row[0])
        return out
    for first in range(0, len(wanted), KEY_CHUNK):
        chunk = wanted[first : first + KEY_CHUNK]
        where, where_params = _matching(client_type, chunk, own)
        union, params = _union(pieces, where, where_params, columns=KEY_COLUMNS)
        rows = conn.execute(
            f"SELECT {own} AS k, count(DISTINCT {peer}) AS n FROM ({union}) GROUP BY k",  # noqa: S608 (constants)
            params,
        ).fetchall()
        members = set(chunk)
        for row in rows:
            if str(row["k"]) in members:
                out[str(row["k"])] = int(row["n"] or 0)
    return out


def peer_list(
    conn: sqlite3.Connection,
    client_type: str,
    key: str,
    pieces: Sequence[tuple[str, int, int]],
    *,
    limit: int = MAX_PEERS,
) -> dict[str, Any]:
    """One client's peers in the pieces, busiest first: `{total, items: [{key, requests, refused, served,
    last_seen}], basis}` (the IPs of a place, or the places of an IP; caller text, to be shown escaped)."""
    own, peer = _sides(client_type)
    if not key or key == OTHER_KEY or not pieces:
        return {"total": 0, "items": [], "basis": PEERS_BASIS}
    where, where_params = _matching(client_type, [key], own)
    union, params = _union(pieces, where, where_params, key_range=client_type == "ip")
    grouped = (
        f"SELECT {peer} AS peer, sum(requests) AS requests, sum(refused) AS refused, sum(served) AS served, "  # noqa: S608
        f"max(bucket_start) AS last_seen FROM ({union}) WHERE {own} = ? GROUP BY peer"
    )
    bound = [*params, key]
    total = int(conn.execute(f"SELECT count(*) FROM ({grouped})", bound).fetchone()[0])  # noqa: S608 (constant)
    rows = conn.execute(
        f"SELECT * FROM ({grouped}) ORDER BY requests DESC, peer LIMIT ?",  # noqa: S608 (constant)
        [*bound, max(1, min(int(limit), MAX_PEERS))],
    ).fetchall()
    items = [
        {
            "key": str(row["peer"]),
            "requests": int(row["requests"] or 0),
            "refused": int(row["refused"] or 0),
            "served": int(row["served"] or 0),
            "last_seen": int(row["last_seen"]) if row["last_seen"] is not None else None,
        }
        for row in rows
    ]
    return {"total": total, "items": items, "basis": PEERS_BASIS}


def attach_last_seen(
    conn: sqlite3.Connection, client_type: str, rows: list[dict[str, Any]], pieces: Sequence[tuple[str, int, int]]
) -> None:
    """Set `last_seen` on each row: the start of the newest bucket with a request of that client in the pieces
    (the minute for recent traffic; the hour or day where only compacted rows answer), None without one."""
    keys = [str(row["key"]) for row in rows]
    wanted = set(keys)
    newest: dict[str, int] = {}

    def take(found: Iterable[sqlite3.Row]) -> None:
        for row in found:
            name = str(row["client_key"])
            if row["newest"] is not None and name in wanted:
                newest[name] = max(newest.get(name, 0), int(row["newest"]))

    for table, lo, hi in pieces:
        base = (
            f"SELECT client_key, max(bucket_start) AS newest FROM {table} WHERE client_type = ? "  # noqa: S608 (names)
            "AND bucket_start >= ? AND bucket_start < ?"
        )
        if len(keys) > KEY_CHUNK * WHOLE_WINDOW_CHUNKS:
            # Sorting a whole window by last seen: one pass over the window beats many key lists.
            take(conn.execute(f"{base} GROUP BY client_key", (client_type, int(lo), int(hi))))
            continue
        for first in range(0, len(keys), KEY_CHUNK):
            chunk = keys[first : first + KEY_CHUNK]
            marks = ", ".join("?" for _ in chunk)
            take(
                conn.execute(
                    f"{base} AND client_key IN ({marks}) GROUP BY client_key", (client_type, int(lo), int(hi), *chunk)
                )
            )
    for row in rows:
        row["last_seen"] = newest.get(str(row["key"]))


def recorded_scores(conn: sqlite3.Connection, keys: Iterable[str], since: int) -> dict[str, dict[str, Any]]:
    """`{address: {score, score_last, at, hour}}`: each address's latest recorded hour since `since` (fleet-wide)."""
    wanted = [key for key in dict.fromkeys(str(k) for k in keys) if key and key != OTHER_KEY]
    out: dict[str, dict[str, Any]] = {}
    for first in range(0, len(wanted), KEY_CHUNK):
        chunk = wanted[first : first + KEY_CHUNK]
        marks = ", ".join("?" for _ in chunk)
        rows = conn.execute(
            "SELECT client_key, bucket_start, score_max, score_last, last_at FROM client_score_hour "  # noqa: S608
            f"WHERE bucket_start >= ? AND client_key IN ({marks}) ORDER BY bucket_start DESC",
            (int(since), *chunk),
        ).fetchall()
        for row in rows:  # newest hour first: the first row of an address is its latest hour
            out.setdefault(
                str(row["client_key"]),
                {
                    "score": int(row["score_max"]),
                    "score_last": int(row["score_last"]),
                    "at": int(row["last_at"]),
                    "hour": int(row["bucket_start"]),
                },
            )
    return out


__all__ = [
    "KEY_CHUNK",
    "MAX_PEERS",
    "OTHER_KEY",
    "PEERS_BASIS",
    "SCORE_BASIS",
    "attach_last_seen",
    "peer_counts",
    "peer_list",
    "recorded_scores",
]
