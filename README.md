# port-index

One page linking to every HTTP server running on a machine, so you don't have
to remember which port each `uvicorn` is on.

Standard library only (Python 3.8+), Linux only. Every request re-scans, so the
page is always current.

```
python3 portindex.py                 # http://<server>:8000/
```

## Modes

| `--mode` / `PORTINDEX_MODE` | How it finds servers | Use when |
|---|---|---|
| `scan` (default) | Reads `/proc/net/tcp{,6}` for listening ports, probes each with `GET /`, lists whatever answers HTTP | Servers started by hand, systemd units, anything on the host |
| `docker` | Asks the Docker daemon for running containers; lists their published ports and any Traefik `Host()` / `PathPrefix()` routes found in their labels | Apps live in `docker compose`, optionally behind Traefik |

**scan mode** labels each entry with the page's `<title>` (or the `info.title`
from `/openapi.json` for FastAPI-style apps) and the process command line, and
flags servers bound to `127.0.0.1` that won't be reachable from other machines.
Run it as the same user as your servers (or root) to see command lines. Only
things that actually speak HTTP are listed; `SKIP_PORTS` excludes known
non-HTTP services from probing.

**docker mode** names entries from the `portindex.title` label, else the compose
service name, else the container name. Containers with no route and no
published port (databases, workers) are not listed; `portindex.hide: "true"`
hides anything else. No probing, so the page is instant. Run it on the host
(user in the `docker` group) or as a container with the socket mounted — see
[`compose.yaml`](compose.yaml) for a complete Traefik + port-index stack.

## Settings

| Flag | Env var | Default |
|---|---|---|
| `--mode` | `PORTINDEX_MODE` | `scan` |
| `--port` | `PORTINDEX_PORT` | `8000` |
| `--docker` | `PORTINDEX_DOCKER` | `/var/run/docker.sock` (or `tcp://host:2375`) |
| `--proxy-port` | `PORTINDEX_PROXY_PORT` | `80` — Traefik's HTTP entrypoint, for `Host()` links |

## Running it permanently (scan mode)

```ini
# /etc/systemd/system/portindex.service
[Unit]
Description=index of HTTP servers on this host
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/portindex/portindex.py
Restart=always

[Install]
WantedBy=multi-user.target
```
