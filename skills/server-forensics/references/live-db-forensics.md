# Live RDBMS forensics (MySQL / MariaDB)

Answers about PII, counts, totals, group ownership, and table names usually come from a live database. Prefer a structured query over string search.

## Connect

If the DB is on the host and accepts the host bridge/client connection:

```bash
mysql -u <user> -p<password> -h 127.0.0.1 -P <port> -e "SQL"
```

Many containerized MySQL grants reject connections from the **host bridge IP**. In that case connect from inside the container over its localhost (see container-evidence.md):

```bash
docker exec <container> mysql -u<user> -p<password> -e "SQL"
```

Never put credentials in a quoted variable that re-adds the quotes. Use `--password=<pw>` or `-p<pw>` directly; avoid `-p'<pw>'` (the single quotes become part of the password).

## Enumerate before assuming table names

```sql
SHOW DATABASES;
USE <db>;
SHOW TABLES;
DESCRIBE <table>;          -- columns, types, keys
```

Do **not** guess the table from the answer string. Find the table whose schema matches the claim (a `telnum`/`mtel` column for phones, a `memail` for emails, a `money` for amounts, an `owner_id` for group ownership).

## PII lookup by a stable key

Names are often mangled by encoding (mojibake) in course databases, so a `WHERE mname='<target_name>'` returns nothing. Search by an alternate stable key instead:

```sql
-- by phone
SELECT * FROM users_company_ys WHERE mtel = '<target_phone>';
-- by email (case-insensitive, on the Latin mailbox which survives encoding)
SELECT * FROM users_person_ys WHERE LOWER(memail) = '<target_email>';
```

Then read back the target field (name, phone, email) from the matched row. State which key you used and why.

## Aggregation (totals / amounts)

```sql
SELECT SUM(money) FROM cv_loanbill WHERE <predicate>;
```

Convert units explicitly for the answer format. Example: `SUM(money)=12345678.90` yuan → `1234.57万元` (divide by 10,000, keep two decimals). Show the raw sum and the conversion so the answer is reproducible.

## Counts and sets

```sql
SELECT COUNT(*) FROM im_group;                       -- number of groups
SELECT COUNT(*) FROM im_group_member WHERE group_id=<group_id>; -- members of one group
```

Define the predicate explicitly (which group, which status). A count without a predicate is not defensible.

## Identity / relationship (ownership)

```sql
SELECT owner_id FROM im_group WHERE gname='<group_name>';   -- resolves to an owner id
SELECT user_name FROM im_user WHERE id=<owner_id>;          -- resolves to the owner name
```

Join through stable IDs: `owner_id` → `im_user.id`. Do not equate `gname` strings across tables.

## Password-hash format detection

Inspect the stored hash prefix to name the algorithm — do not guess from the presence of a crypto library.

```sql
SELECT password FROM im_user LIMIT 3;
```

```text
$2a$10$...   → bcrypt
$2y$..$...   → bcrypt (PHP variant)
$1$...       → md5 (unix crypt)
$2b$...      → bcrypt
sha1:...     → SHA-1 (often unsalted, lowercase hex)
40-hex no prefix → SHA-1 candidate; 32-hex → MD5 candidate (confirm by context)
```

Report the algorithm the prefix proves. "bcrypt" answers a "password encryption method" question; the `$2a$10$` prefix is the evidence.

## Table-name questions

```sql
SHOW TABLES LIKE '%message%';
SELECT TABLE_NAME FROM information_schema.tables
  WHERE table_schema='<platform_db>' AND table_name LIKE '%private%';
```

The matched table name (e.g. `<private_message_table>`) is the answer; report it verbatim.

## Discipline

- `SELECT` only. No `UPDATE/DELETE/DROP`.
- Record `db.table` + row key + column as the locator.
- Distinguish the configured port from the host-published port when connecting (service-port-enum.md).
- If a needed table is in a different database/container, locate and connect to that one separately; do not assume one connection sees all data.
