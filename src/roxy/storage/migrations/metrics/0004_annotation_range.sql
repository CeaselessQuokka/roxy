-- kind: expand
-- The end of a ranged data reset on its chart marker (plan 6.8; written by roxy/metrics/annotate.py).
--
-- A reset of one time range deletes the counters of [at, until); the marker sits at the range start. With `until`
-- stored, a KPI window strictly inside the deleted range still gets its partial-data notice
-- (`metrics/queries.py reset_annotations` tests the overlap). NULL for every other marker, and for markers written
-- by the previous release, which keeps working on this schema because it never names the column.

ALTER TABLE annotations ADD COLUMN until INTEGER;
