# Containerized evidence access

Web/application servers in courses are frequently Dockerized. The evidence (DB, files, jars) lives inside containers or their volumes. Access it read-only.

## Map containers to evidence

```bash
docker ps -a
docker inspect <id> -f '{{.Name}} {{.State.Status}} {{json .NetworkSettings.Ports}}'
docker inspect <id> -f '{{json .Mounts}}'     # volume / bind mounts
```

Note which container holds the database vs the app vs the chat backend, and its published ports.

## Read a DB that only listens inside the container

A MySQL container typically grants `root@'%'` or `root@localhost` but **rejects the host bridge IP** (`172.x.x.x`). Connecting from the host with `mysql -h 127.0.0.1 -P <published>` can fail with "Access denied for user 'root'@'172...'".

Fix: run the client **inside** the container, where it connects over the container's loopback:

```bash
docker exec <container> mysql -u<user> -p<password> -e "SQL"
```

This reaches `localhost:3306` inside the container and satisfies the grant. Use `--password=<pw>` to avoid quote-injection bugs.

## Start an Exited evidence container for read access

If the evidence container is stopped, you may need it running to read its DB:

```bash
docker start <container>          # brings up mysqld inside
# then docker exec the mysql client as above; SELECT only
```

Note in the report that you started the container solely to read its data; do not alter its contents. If the task requires returning it to the original stopped state, `docker stop` it afterward.

## Find a service's port from its own config

```bash
docker exec <container> cat /app/im-platform/application.yml | grep -i "server.port"
docker exec <container> cat /app/im-admin/application.yml | grep -i "server.port"
```

The `server.port` inside the container is the **container port**; cross-check with `docker port` for the host-published port (service-port-enum.md).

## Jar / artifact hashing

```bash
docker exec <container> sha256sum /app/im-admin.jar
# take the last 8 hex chars, uppercase if the format requires
```

## Discipline

- `docker inspect`/`exec` are read-only by nature; never `docker rm` or `docker commit` evidence.
- Separate host, image, container instance, and application-layer identities when correlating.
- Record `container -> db -> table -> row` as the locator chain.
