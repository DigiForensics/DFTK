# SQLite / SQL data

Start with schema/table/column semantics before keyword search. Determine primary/stable identifiers and relationships.

For counts, define the row predicate and deduplication key. For identity claims, join through stable IDs where possible. For timestamps, identify storage format/epoch/time zone before comparison.

A matching text field may be a label, cache, deleted remnant, or unrelated record; use row/table relationships to establish meaning.
