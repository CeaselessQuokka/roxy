"""Storage: the four SQLite databases every worker process shares.

What this is
    The package that owns every byte Roxy keeps on disk: connections and threads (`db.py`), the schema and its
    migrations (`migrate.py`, `migrations/`), batched metric writes (`batch.py`), leases for leader election,
    single-flight and tarpit slots (`leases.py`), and pruning and maintenance (`retention.py`).

Why it exists
    Plan 6.1: several worker processes (and, during a deploy, two colors of workers) must share state through
    files that stay fast to read and write. SQLite in WAL mode gives that without another daemon to run.

How it works
    Other packages never open SQLite themselves. They receive a `Database` from `ctx.dbs` and hand it small
    functions to run inside a transaction (`await db.write(fn)`, `await db.read(fn)`).

What to read next
    `roxy/storage/db.py`, then `roxy/storage/migrate.py`.
"""
