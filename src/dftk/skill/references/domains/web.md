# Web / server-side artifacts

Use structured access/config/application logs when available. Separate configured routes/domains from requests actually observed.

For client IP claims, account for reverse proxies and forwarded headers only when the server/proxy configuration establishes their trust semantics. A header value by itself is not necessarily the originating client IP.
