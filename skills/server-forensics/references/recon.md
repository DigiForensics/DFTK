# Recon — initial triage

Run a small, fixed set of read-only commands on first contact. The goal is to map the box and locate application roots before any deep search.

## Host identity and disks

```bash
cat /etc/os-release
uname -a
blkid                 # partition + filesystem UUIDs (see partition-identity.md)
lsblk -o NAME,MAJ:MIN,FSTYPE,UUID,PARTUUID,MOUNTPOINT,SIZE
```

## Listening services and processes

```bash
ss -tlnp              # TCP listeners with owning process (needs root for -p)
ss -ulnp              # UDP listeners
ps aux                # running processes, args, working dirs
```

`ss -tlnp` output: `LISTEN 0 128 0.0.0.0:3306 ... users:(("mysqld",pid=...))`. The number after `:` is the **local listening port**. For a containerized service, this is the *container* port; the *host-published* port comes from `docker port` / `docker inspect` (see service-port-enum.md).

## Containers

```bash
docker ps -a          # all containers, ports, status
docker images
docker inspect <id>   # mounts, env, exposed ports, cmd
```

## Locate application roots

Course/web servers usually live under a few predictable places. Scope searches; do **not** `find /` across the whole filesystem (slow, and usually unnecessary).

```bash
ls -d /root/* /srv/* /opt/* /var/www/* 2>/dev/null
# then inside a candidate root:
ls -la <app_root>
grep -rlni "password\|dbhost\|dbuser\|dsn" <app_root>/App/Conf <app_root>/config 2>/dev/null
```

## What to record

- OS and kernel
- every listening port and its owning process
- container names, published ports, mount sources
- candidate application roots and their config file paths

This inventory is the map for the rest of the investigation; reuse it across questions instead of re-discovering each time.
