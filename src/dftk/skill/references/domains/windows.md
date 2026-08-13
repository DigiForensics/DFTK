# Windows

Potential structured sources include Registry hives, USB/device artifacts, EVTX, browser data, and filesystem metadata. Optional Registry/EVTX parsers may be unavailable; `unsupported` is a capability limitation, not a negative finding.

Maintain hive/log provenance and event semantics. Convert identifiers/SIDs only when a reliable mapping exists. Event ID presence alone may require event-field interpretation to establish the requested behavior.
