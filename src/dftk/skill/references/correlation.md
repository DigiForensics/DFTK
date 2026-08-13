# Correlation

Correlation turns separate observations into a claim. Require a defensible join.

## Strong joins
- stable user/account/device ID;
- primary/foreign-key relationship;
- session/request/message/transaction ID;
- exact content/source hash;
- explicit code call/data-flow relation;
- authenticated identity + remote IP + event time;
- unique artifact path plus matching source identity.

## Conditional joins
Time proximity, IP equality, display names, URL/domain similarity, or nearby strings can support a relationship but rarely prove it alone. Combine them with independent context.

## Time correlation
Record:
- original timestamp value;
- parsed time zone/assumption;
- source event semantics;
- clock/source limitations.

Do not silently compare local time, UTC, Unix seconds, WebKit microseconds, FAT timestamps, or application-specific epochs as if they share semantics.

## Identity collisions
Names, phone numbers, email addresses, IPs, device names, and usernames can be reused. Prefer stable IDs and source-specific keys.
