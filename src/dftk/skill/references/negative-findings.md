# Negative findings

Absence is harder to prove than presence.

A defensible negative finding normally requires:
- a capability that can detect the target class;
- successful execution (`ok`, or a `partial` whose limitation does not affect the relevant scope);
- meaningful coverage of the relevant source(s);
- no warning/error that invalidates the search space;
- a query/predicate broad enough for the claim.

Never convert these into “not present”:
- `unsupported`
- `error`
- `blocked`
- dependency missing
- encrypted/inaccessible source
- truncated/incomplete artifact
- one narrow keyword search returning zero hits
- parser that only covers one representation of the behavior

Phrase scope honestly, e.g.:

> “No matching record was found in the parsed `messages` table under this predicate.”

This is stronger and more reproducible than:

> “No message exists.”
