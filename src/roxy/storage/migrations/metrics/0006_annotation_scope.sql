-- kind: expand
-- What a data reset deleted, on its chart marker (plan 6.8, finding parity-12; written by roxy/metrics/annotate.py).
--
-- A JSON list of `<db>.<table>` names, `<db>.<table>#latency` for rollup rows whose latency histograms were emptied
-- (counts kept), and `<db>.<table>#cache_state` for rollup rows whose cache lookup state a cache statistics reset
-- cleared (requests kept). A KPI tile or chart whose data a reset did not touch keeps its delta and shows no notice
-- (`metrics/queries.py reset_touches`). NULL on every other marker and on markers written before this column
-- existed; readers then treat the marker as touching every number (the safe reading). The previous release never
-- names the column, so it keeps working on this schema during a deploy.

ALTER TABLE annotations ADD COLUMN reset_tables TEXT;
