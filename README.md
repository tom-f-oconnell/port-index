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
| `scan` (default) | Reads `/proc/net/tcp{,6}` for listening ports, probes each with `GET /`, lists whatever serves a web page | Servers started by hand, systemd units, anything on the host |
| `docker` | Asks the Docker daemon for running containers; lists their published ports and any Traefik `Host()` / `PathPrefix()` routes found in their labels | Apps live in `docker compose`, optionally behind Traefik |

Both modes leave out ports bound to localhost only, since other machines can't
reach them, and system ports (below 1024, except 80), such as CUPS on 631.

**scan mode** labels each entry with the page's `<title>` (or the `info.title`
from `/openapi.json` for FastAPI-style apps) and the process command line. Run
it as the same user as your servers (or root) to see command lines. Only web
pages are listed: `/` must return HTML (other than a 404), or the app must have
an OpenAPI title, so bare APIs like Elasticsearch or MinIO are left out.
`SKIP_PORTS` excludes known non-HTTP services from probing.

**docker mode** names entries from the `portindex.title` label, else the compose
service name, else the container name. Containers with no route and no
published port (databases, workers) are not listed; `portindex.hide: "true"`
hides anything else, including bare APIs, since nothing is probed. That also
makes the page instant. Run it on the host
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

From this folder, copy the script and [`portindex.service`](portindex.service)
into place, start the service, now and on every boot, and check that it's running:

```
sudo install -D -m 755 portindex.py /opt/portindex/portindex.py
sudo install -D -m 644 portindex.service /etc/systemd/system/portindex.service
sudo systemctl daemon-reload
sudo systemctl enable --now portindex
systemctl status portindex
```

The service runs as root, so it can see the command line of every server.

- **Another port:** if 8000 is taken, run `sudo systemctl edit portindex`, add the
  lines below, then run `sudo systemctl restart portindex`. This is kept separately
  from the installed unit, so updating won't overwrite it.

  ```ini
  [Service]
  Environment=PORTINDEX_PORT=<port>
  ```
- **Updating:** repeat the two `install` commands, then run
  `sudo systemctl daemon-reload` and `sudo systemctl restart portindex`.
- **Logs:** `journalctl -u portindex`
