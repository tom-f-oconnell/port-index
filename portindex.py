#!/usr/bin/env python3
"""portindex.py -- one page linking to every HTTP server on this box.

Two discovery modes, chosen with --mode or PORTINDEX_MODE (default: scan):

  scan    Read /proc for listening TCP ports, probe each one, and list
          whatever serves a web page: HTML at /, or an OpenAPI title (FastAPI
          & co). Sees uvicorn started by hand, systemd units, containers with
          published ports. Run it on the host (inside a container it would
          only see that container).

  docker  Ask the Docker daemon for running containers and list their
          published ports plus any Traefik Host()/PathPrefix() routes found
          in their labels. No probing, so bare APIs are only left out via
          `portindex.hide`. Names come from the `portindex.title`
          label, else the compose service name, else the container name.
          Run it on the host (user in the `docker` group) or as a container
          with the socket mounted -- see compose.yaml.

Both modes leave out ports bound to localhost only, which other machines can't
reach, and system ports (below 1024, except 80).

Settings, as a flag or an environment variable:

  --mode        PORTINDEX_MODE        scan | docker               [scan]
  --port        PORTINDEX_PORT        port to serve the index on  [8000]
  --docker      PORTINDEX_DOCKER      socket path or tcp://host:port
                                                 [/var/run/docker.sock]
  --proxy-port  PORTINDEX_PROXY_PORT  Traefik's HTTP port, for Host() links [80]

Container labels honoured in docker mode:
  portindex.title=<text>   name to show      portindex.hide=true   leave it out

Standard library only; Linux only. Every request re-scans, so the page is
always current.
"""
import argparse
import html
import http.client
import json
import os
import re
import socket
import struct
import urllib.error
import urllib.request
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SKIP_PORTS = {22, 5432}     # known non-HTTP services: never list or probe
PROBE_TIMEOUT = 1.0         # scan mode: seconds per port (probes run in parallel)

# One row on the page. links = [(text, url), ...]
Entry = namedtuple("Entry", "title links detail meta")


def is_loopback(ip):
    return ip == "::1" or ip.startswith(("127.", "::ffff:127."))


def system_port(port):
    """Whether port is reserved for system services (CUPS, ...), rather than web apps."""
    return port < 1024 and port != 80


# --------------------------------------------------------------------------
# scan mode: /proc + HTTP probes
# --------------------------------------------------------------------------

def _ip(hexaddr):
    """Decode the little-endian hex address column of /proc/net/tcp{,6}."""
    if len(hexaddr) == 8:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(hexaddr, 16)))
    words = [struct.pack("<I", int(hexaddr[i:i + 8], 16)) for i in range(0, 32, 8)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def socket_inodes():
    """{socket inode: pid} for every process whose fds we're allowed to read."""
    inodes = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                inodes[int(link[8:-1])] = int(pid)
    return inodes


def listening_ports():
    """{port: cmdline} for TCP listeners other machines can reach (v4 + v6, deduped)."""
    inodes = socket_inodes()
    ports = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if cols[3] != "0A":              # 0A == LISTEN
                continue
            addr, port = cols[1].rsplit(":", 1)
            port = int(port, 16)
            # checked per listener: a port can be bound to loopback and a public address
            if port in ports or is_loopback(_ip(addr)):
                continue
            cmd = ""
            pid = inodes.get(int(cols[9]))
            if pid:
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
                except OSError:
                    pass
            ports[port] = cmd
    return ports


def fetch(url):
    """(status, content-type, body) or None if nothing HTTP answers."""
    req = urllib.request.Request(url, headers={"User-Agent": "portindex"})
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read(65536)
    except urllib.error.HTTPError as e:      # 4xx/5xx: still an HTTP server
        return e.code, e.headers.get("Content-Type", ""), b""
    except Exception:                        # refused, timed out, not HTTP
        return None


def probe(port):
    """(status, title) if port serves a page for people, else None.

    Bare APIs (Elasticsearch, MinIO, ...) answer HTTP but have nothing to show at /.
    """
    base = f"http://127.0.0.1:{port}"
    res = fetch(base + "/")
    if res is None:
        return None
    status, ctype, body = res
    title = ""
    if "html" in ctype:
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            title = html.unescape(m.group(1).decode(errors="replace").strip())
    if not title:                            # FastAPI & co: use the OpenAPI title
        o = fetch(base + "/openapi.json")
        if o and o[0] == 200:
            try:
                title = json.loads(o[2])["info"]["title"]
            except (ValueError, KeyError, TypeError):
                pass
    if not title and ("html" not in ctype or status == 404):
        return None
    return status, title


def scan_entries(host, cfg, my_port):
    ports = {p: cmd for p, cmd in listening_ports().items()
             if p != my_port and p not in SKIP_PORTS and not system_port(p)}
    with ThreadPoolExecutor(max_workers=32) as ex:
        results = list(ex.map(probe, ports))
    entries = []
    for port, res in sorted(zip(ports, results)):
        if res is None:
            continue
        status, title = res
        entries.append(Entry(title, [(f":{port}", f"http://{host}:{port}/")],
                             f"[{status}]", ports[port]))
    return entries


# --------------------------------------------------------------------------
# docker mode: Docker Engine API + Traefik labels
# --------------------------------------------------------------------------

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.sock_path = sock_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.sock_path)


def docker_get(where, path):
    """GET a JSON endpoint of the Docker Engine API."""
    if where.startswith("tcp://"):
        conn = http.client.HTTPConnection(where[len("tcp://"):], timeout=5)
    else:
        conn = UnixHTTPConnection(where, timeout=5)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        data = json.loads(r.read())
    except OSError as e:
        raise OSError(f"cannot reach Docker at {where} ({e.strerror or e}); "
                      "is the socket mounted, and are you in the docker group?") from e
    finally:
        conn.close()
    if r.status != 200:
        raise RuntimeError(data.get("message", r.reason))
    return data


RULE_HOST = re.compile(r"\bHost\(([^)]*)\)")
RULE_PATH = re.compile(r"\bPathPrefix\(([^)]*)\)")
BACKTICKED = re.compile(r"`([^`]*)`")


def traefik_urls(labels, proxy_port):
    """URLs implied by traefik.http.routers.<name>.rule labels."""
    if labels.get("traefik.enable") == "false":
        return []
    port = "" if proxy_port == 80 else f":{proxy_port}"
    urls = []
    for key, rule in labels.items():
        if not (key.startswith("traefik.http.routers.") and key.endswith(".rule")):
            continue
        hosts = [h for m in RULE_HOST.finditer(rule) for h in BACKTICKED.findall(m.group(1))]
        paths = [p for m in RULE_PATH.finditer(rule) for p in BACKTICKED.findall(m.group(1))]
        path = paths[0] if paths else "/"
        urls += [f"http://{h}{port}{path}" for h in hosts]
    return urls


def docker_entries(host, cfg, my_port):
    entries = []
    for c in docker_get(cfg.docker, "/containers/json"):
        labels = c.get("Labels") or {}
        if labels.get("portindex.hide") == "true":
            continue
        title = (labels.get("portindex.title")
                 or labels.get("com.docker.compose.service")
                 or c["Names"][0].lstrip("/"))
        links = [(u.split("://", 1)[1].rstrip("/"), u)
                 for u in traefik_urls(labels, cfg.proxy_port)]
        published = [p for p in c.get("Ports", [])
                     if p.get("PublicPort") and p.get("Type") == "tcp"
                     and p["PublicPort"] not in SKIP_PORTS
                     and p.get("PrivatePort") not in SKIP_PORTS
                     and not system_port(p["PublicPort"])
                     and not is_loopback(p.get("IP", ""))]
        for port in sorted({p["PublicPort"] for p in published}):
            links.append((f":{port}", f"http://{host}:{port}/"))
        if not links:
            continue                         # internal-only container: db, worker...
        entries.append(Entry(title, links, c.get("Status", ""), c.get("Image", "")))
    return sorted(entries, key=lambda e: e.title.lower())


MODES = {"scan": scan_entries, "docker": docker_entries}


# --------------------------------------------------------------------------
# the page
# --------------------------------------------------------------------------

STYLE = """<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:60em;margin:2em auto;padding:0 1em}
li{margin-bottom:.8em} a{font-size:1.2em;margin-right:.4em} code{color:#555;font-size:.85em}
small{color:#777} .warn{color:#b00} h1 small{font-size:.5em;font-weight:normal}
</style>"""


def row(e):
    links = "".join(f"<a href='{html.escape(u)}'>{html.escape(t)}</a>" for t, u in e.links)
    return (f"<li>{links}<b>{html.escape(e.title)}</b> <small>{html.escape(e.detail)}</small>"
            f"<br><code>{html.escape(e.meta)}</code></li>")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        cfg = self.server.cfg
        # link to whatever hostname the browser used to reach this page
        host = re.sub(r":\d+$", "", self.headers.get("Host", "localhost"))
        try:
            entries = MODES[cfg.mode](host, cfg, self.server.server_address[1])
            body = "\n".join(map(row, entries)) or "<li>no HTTP servers found</li>"
        except Exception as e:
            body = (f"<li class=warn>{cfg.mode} mode failed: "
                    f"{html.escape(f'{type(e).__name__}: {e}')}</li>")
        h = html.escape(host)
        page = (f"<!doctype html><title>servers on {h}</title>{STYLE}"
                f"<h1>HTTP servers on {h} <small>{cfg.mode} mode</small></h1>"
                f"<ul>{body}</ul>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *args):
        pass


def main():
    def env(name, default):
        return os.environ.get("PORTINDEX_" + name, default)

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=list(MODES), default=env("MODE", "scan"))
    ap.add_argument("--port", type=int, default=int(env("PORT", 8000)))
    ap.add_argument("--docker", metavar="SOCK_OR_URL",
                    default=env("DOCKER", "/var/run/docker.sock"))
    ap.add_argument("--proxy-port", type=int, default=int(env("PROXY_PORT", 80)))
    cfg = ap.parse_args()

    srv = ThreadingHTTPServer(("0.0.0.0", cfg.port), Handler)
    srv.cfg = cfg
    print(f"portindex ({cfg.mode} mode) on http://0.0.0.0:{cfg.port}/", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
