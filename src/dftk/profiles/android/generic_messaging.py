# Demo profile: generic Android messaging — DFTK 3.5.0.
#
# This profile proves the ArtifactProfile model without hard-coding a vendor
# parser. It matches any SQLite database exposing a message-like table and
# normalises it to {timestamp, sender, body, thread}. Confidence is low by
# design: a generic match is a *hypothesis* about the data, not a proven
# attribution of a specific application.

from dftk.profiles import ArtifactProfile, get_profile_registry

PROFILE = ArtifactProfile(
    id="android.generic_messaging",
    platform="android",
    app_name="Generic Android messaging (demo)",
    description=(
        "Generic SMS/MMS-style message store: a message table with body/date/address "
        "columns and epoch-millisecond timestamps."
    ),
    db_globs=(
        "data/data/*/databases/*.db",
        "data/data/*/databases/mm*.db",
        "data/user/*/*/databases/*.db",
    ),
    detect_tables=("messages", "sms", "msg", "message"),
    detect_columns=("body", "date", "address", "thread_id"),
    table="messages",
    field_map={
        "timestamp": "date",
        "sender": "address",
        "body": "body",
        "thread": "thread_id",
    },
    time_format="epoch_ms",
    time_fields=("timestamp",),
    encoding="utf-8",
    attachments=(
        "attachments are referenced indirectly (media tables / row ids); this demo "
        "profile does not dereference them"
    ),
    confidence="low",
)

get_profile_registry().register(PROFILE)
