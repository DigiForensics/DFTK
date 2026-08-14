# Service and port enumeration

Questions about "the (external/exposed) port number" of a service need care: there are up to three different port numbers, and the question wording decides which one is correct.

## Three port numbers

```text
container port      — the port the process listens on inside the container (e.g. 3306)
host-published port — the port the container maps to on the host  (e.g. 3399 -> 3306)
proxy/ingress port  — the port a reverse proxy or web server exposes to clients (e.g. 8085)
```

## Where each comes from

```bash
ss -tlnp                                  # host-level listeners (native services, proxies)
docker ps                                 # shows 0.0.0.0:3399->3306/tcp
docker port <container>                   # explicit host:container mapping
docker inspect <container> -f '{{json .NetworkSettings.Ports}}'
```

For an application reached through a web server, the "对外端口" (externally reachable port) is usually the **proxy/ingress port** shown by `ss -tlnp` on the host, not the container's internal port. Confirm by reading the app's own config or a debug/log line that prints `HTTP_HOST ... :<port>`.

## Mapping process → port → service

```bash
ss -tlnp | grep -E ':(3306|8085|8888|9000) '
ps -o pid,cmd -p <pid_from_ss>            # what binary owns it
```

## "对外端口号" interpretation rule

- If the question means *the port a client connects to*, report the **host-published / ingress** port (`ss` host listener or `docker port`), not the container-internal port.
- If the question means *the database port configured in the app's connection string*, report the **container/internal** port (what the app actually connects to).
- When the two differ, state both and explain which you reported and why. In a course where "对外" literally means externally reachable, prefer the host-published port. Flag the divergence rather than silently picking one.

Example: a MySQL container publishes `3399->3306`. The app connects to `3306` (container port); an external client reaches `3399` (host-published). For a question asking for the database's externally reachable port, answer the host-published port (`3399`) and note that the in-container/configured port is `3306`.
