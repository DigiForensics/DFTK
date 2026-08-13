# Generic artifacts

Start with identity and boundaries: file type, size, source path, hash, container/archive structure, and whether the artifact is complete.

Use structured parsing when the format is recognized. Strings/entropy/encoding are discovery aids, not semantic proof by themselves.

For archives, distinguish source evidence from derived extraction output. Extraction must not modify the original and must remain within an authorized workspace.
