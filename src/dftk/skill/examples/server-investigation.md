# Example — historical login IP

Question: “What historical login IP was used by account X?”

Evidence requirement: an authentication/login event tied to account X (or a stable session/account key) and the remote IP.

Do not answer from registration IP, last-edited config, or an unrelated occurrence of the username/IP. Prefer structured authentication/application logs; correlate through account/session identifiers and event time.
