# Network / PCAP

Separate protocol observation from attribution.

Potential evidence:
- DNS queries/answers;
- HTTP hosts/requests where visible;
- TLS SNI/certificate-related metadata where available;
- endpoint IP/port/protocol;
- timestamps and flow context.

An IP or domain in traffic proves observed communication/context, not automatically ownership, maliciousness, or user identity. Partial captures cannot support broad absence claims.
