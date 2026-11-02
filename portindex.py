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

Each entry shows a PID and start time. In scan mode, these are of the process
listening on the port, which for a container's published port is docker-proxy. In
docker mode, they are of the container's main process, with the PID as the host sees it.

Related servers are nested under a parent, behind an arrow that shows or hides them:
containers in one compose project, ports of one container and, in scan mode, servers
started by another listed server. A project's parent is the container labelled
portindex.parent=true, else the only one with the project's name in its title, else a
header with just that name. Scan mode can only group containers if it can reach Docker.

Settings, as a flag or an environment variable:

  --mode        PORTINDEX_MODE        scan | docker               [scan]
  --port        PORTINDEX_PORT        port to serve the index on  [8000]
  --docker      PORTINDEX_DOCKER      socket path or tcp://host:port
                                                 [/var/run/docker.sock]
  --proxy-port  PORTINDEX_PROXY_PORT  Traefik's HTTP port, for Host() links [80]
  --groups      PORTINDEX_GROUPS      on | off: nest related servers [on]

Container labels honoured in docker mode:
  portindex.title=<text>   name to show      portindex.hide=true   leave it out
And in both modes:
  portindex.parent=true    nest the rest of its compose project under it

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
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SKIP_PORTS = {22, 5432}     # known non-HTTP services: never list or probe
PROBE_TIMEOUT = 1.0         # scan mode: seconds per port (probes run in parallel)

# These hand listening sockets on to the servers they start, so a server also holding
# the socket is the one to report. dockerd does this via docker-proxy's -use-listen-fd.
SOCKET_BROKERS = {b"systemd", b"dockerd"}

# One row on the page. links = [(text, url), ...]; started is a datetime; pid and started
# are None if unknown. Entries sharing a group are related, and main marks one known to
# be the parent of the rest.
Entry = namedtuple("Entry", "title links detail meta pid started group main")


def is_loopback(ip):
    return ip == "::1" or ip.startswith(("127.", "::ffff:127."))


def system_port(port):
    """Whether port is reserved for system services (CUPS, ...), rather than web apps."""
    return port < 1024 and port != 80


def names_group(title, group):
    """Whether title has the group's name as whole words, ignoring case and separators."""
    words = re.findall(r"[a-z0-9]+", group.lower())
    return bool(re.search(r"\b" + r"[\W_]*".join(words) + r"\b", title, re.I))


def group_parent(group, members):
    """Which member of a group to nest the others under, or None if none clearly is."""
    if len(members) == 1:
        return members[0]
    marked = [e for e in members if e.main]
    if marked:
        return marked[0]
    named = [e for e in members if names_group(e.title, group)]
    return named[0] if len(named) == 1 else None


def nest(entries, cfg):
    """[(parent Entry, [child Entry, ...]), ...] from entries, in their order.

    A group with no clear parent gets a header, which is an Entry with no links, in place
    of its first member.
    """
    if cfg.groups == "off":
        return [(e, []) for e in entries]
    groups = defaultdict(list)
    for e in entries:
        groups[e.group].append(e)
    rows = []
    for group, members in groups.items():
        parent = group_parent(group, members)
        position = entries.index(parent or members[0])
        children = [e for e in members if e is not parent]
        rows.append((position,
                     parent or Entry(group, [], "", "", None, None, group, False),
                     children))
    return [r[1:] for r in sorted(rows, key=lambda r: r[0])]


# --------------------------------------------------------------------------
# scan mode: /proc + HTTP probes
# --------------------------------------------------------------------------

# The process behind a port. started is a datetime; pid and started are None if unknown.
Proc = namedtuple("Proc", "pid started cmd")

# Parts of /proc/<pid>/stat. start is in clock ticks since boot.
Stat = namedtuple("Stat", "comm ppid start")


def _ip(hexaddr):
    """Decode the little-endian hex address column of /proc/net/tcp{,6}."""
    if len(hexaddr) == 8:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(hexaddr, 16)))
    words = [struct.pack("<I", int(hexaddr[i:i + 8], 16)) for i in range(0, 32, 8)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def socket_inodes():
    """{socket inode: {pid, ...}} for every process whose fds we're allowed to read."""
    inodes = defaultdict(set)
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
                inodes[int(link[8:-1])].add(int(pid))
    return inodes


def boot_time():
    """Seconds since the epoch at boot, which process start times count from."""
    with open("/proc/stat") as f:
        return int(re.search(r"^btime (\d+)$", f.read(), re.M).group(1))


def proc_stat(pid):
    """Stat of a process, from /proc/<pid>/stat."""
    with open(f"/proc/{pid}/stat", "rb") as f:
        stat = f.read()
    # comm is in parens, and can itself contain spaces and parens
    start, end = stat.index(b"("), stat.rindex(b")")
    fields = stat[end + 1:].split()
    return Stat(stat[start + 1:end], int(fields[1]), int(fields[19]))


def listener_process(pids, boot):
    """Proc to report for a port held by pids, with unknown fields if there are none.

    Forked workers share their parent's socket, so this is the oldest holder: the parent,
    which is what was started by hand and is unaffected by workers restarting.
    """
    stats = {}
    for pid in pids:
        try:
            stats[pid] = proc_stat(pid)
        except OSError:                      # already exited
            pass
    if not stats:
        return Proc(None, None, "")
    pid = min(stats, key=lambda p: (stats[p].comm in SOCKET_BROKERS, stats[p].start, p))
    secs = boot + stats[pid].start / os.sysconf("SC_CLK_TCK")
    cmd = ""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        pass
    return Proc(pid, datetime.fromtimestamp(secs, timezone.utc), cmd)


def listening_ports():
    """{port: Proc} for TCP listeners other machines can reach (v4 + v6, deduped)."""
    inodes = socket_inodes()
    holders = defaultdict(set)
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
            if is_loopback(_ip(addr)):
                continue
            holders[port] |= inodes.get(int(cols[9]), set())
    boot = boot_time()
    return {port: listener_process(pids, boot) for port, pids in holders.items()}


def top_listed_ancestor(pid, listed):
    """The highest ancestor of pid in the set listed, or pid itself if there are none."""
    top = pid
    try:
        while pid > 1:
            pid = proc_stat(pid).ppid
            if pid in listed:
                top = pid
    except OSError:                          # exited while walking up
        pass
    return top


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
    ports = {p: proc for p, proc in listening_ports().items()
             if p != my_port and p not in SKIP_PORTS and not system_port(p)}
    with ThreadPoolExecutor(max_workers=32) as ex:
        results = list(ex.map(probe, ports))
    listed = {port: res for port, res in sorted(zip(ports, results)) if res is not None}
    pids = {ports[port].pid for port in listed}
    containers = published_containers(cfg.docker)
    roots = {}
    entries = []
    for port, (status, title) in listed.items():
        proc = ports[port]
        if port in containers:
            group, main = docker_group(containers[port])
        elif proc.pid:
            root = top_listed_ancestor(proc.pid, pids)
            group, main = roots.setdefault(root, f":{port}"), proc.pid == root
        else:
            group, main = f":{port}", False
        entries.append(Entry(title, [(f":{port}", f"http://{host}:{port}/")],
                             f"[{status}]", proc.cmd, proc.pid, proc.started, group, main))
    return nest(entries, cfg)


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


def docker_time(stamp):
    """Parse a Docker timestamp, always UTC, like 2026-11-02T19:52:52.557054839Z."""
    return datetime.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def docker_group(c):
    """(group name, whether it's labelled as the group's parent) for a listed container."""
    labels = c.get("Labels") or {}
    return (labels.get("com.docker.compose.project") or c["Names"][0].lstrip("/"),
            labels.get("portindex.parent") == "true")


def published_containers(where):
    """{published TCP port: listed container}, or {} if Docker can't be reached."""
    try:
        containers = docker_get(where, "/containers/json")
    except (OSError, RuntimeError, ValueError, http.client.HTTPException):
        return {}
    return {p["PublicPort"]: c for c in containers for p in c.get("Ports", [])
            if p.get("PublicPort") and p.get("Type") == "tcp"}


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
        try:
            state = docker_get(cfg.docker, f"/containers/{c['Id']}/json")["State"]
        except RuntimeError:                 # removed since it was listed
            continue
        # Pid is 0 while the container is restarting
        entries.append(Entry(title, links, c.get("Status", ""), c.get("Image", ""),
                             state["Pid"] or None, docker_time(state["StartedAt"]),
                             *docker_group(c)))
    entries.sort(key=lambda e: e.title.lower())
    return sorted(nest(entries, cfg), key=lambda r: r[0].title.lower())


MODES = {"scan": scan_entries, "docker": docker_entries}


# --------------------------------------------------------------------------
# the page
# --------------------------------------------------------------------------

STYLE = """<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:60em;margin:2em auto;padding:0 1em}
li{margin-bottom:.8em} a{font-size:1.2em;margin-right:.4em} code{color:#555;font-size:.85em}
small{color:#777} .warn{color:#b00} h1 small{font-size:.5em;font-weight:normal}
.group{list-style:none} summary{list-style:none} summary::-webkit-details-marker{display:none}
details ul{margin-top:.8em;padding-left:1.5em}
.arrow{display:inline-block;width:1.2em;margin-left:-1.2em;font-size:1.2em;cursor:pointer;user-select:none}
.arrow::before{content:"▸"} details[open]>summary .arrow::before{content:"▾"}
</style>"""

# Each reload is a new page, so this remembers which groups are open. It also makes only
# the arrow toggle, so text in the row can be selected. e.detail is 0 from the keyboard.
SCRIPT = """<script>
for (const d of document.querySelectorAll("details")) {
  const key = "portindex.open." + d.dataset.group;
  d.open = localStorage[key] === "1";
  d.addEventListener("toggle", () => { localStorage[key] = d.open ? "1" : "0"; });
  d.querySelector("summary").addEventListener("click", e => {
    if (e.detail && !e.target.closest(".arrow, a")) e.preventDefault();
  });
}
</script>"""


def row(e, related=0):
    """The contents of an entry's list item, saying how many entries are nested under it."""
    links = "".join(f"<a href='{html.escape(u)}'>{html.escape(t)}</a>" for t, u in e.links)
    parts = []
    if e.links:                              # otherwise, a group header: not a server itself
        parts.append(e.detail)
        parts.append(f"pid {e.pid}" if e.pid else "pid unknown")
        parts.append(f"started {e.started.astimezone():%Y-%m-%d %H:%M %Z}" if e.started
                     else "start time unknown")
    if related:
        parts.append(f"{related} related server{'s' if related > 1 else ''}")
    detail = html.escape(" · ".join(parts))
    meta = f"<br><code>{html.escape(e.meta)}</code>" if e.meta else ""
    return f"{links}<b>{html.escape(e.title)}</b> <small>{detail}</small>{meta}"


def group_row(parent, children):
    """A list item for a parent, with an arrow to show or hide any children."""
    if not children:
        return f"<li>{row(parent)}</li>"
    nested = "\n".join(f"<li>{row(c)}</li>" for c in children)
    return (f"<li class=group><details data-group='{html.escape(parent.group)}'>"
            f"<summary><span class=arrow></span>{row(parent, len(children))}</summary>"
            f"<ul>{nested}</ul></details></li>")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        cfg = self.server.cfg
        # link to whatever hostname the browser used to reach this page
        host = re.sub(r":\d+$", "", self.headers.get("Host", "localhost"))
        try:
            rows = MODES[cfg.mode](host, cfg, self.server.server_address[1])
            body = ("\n".join(group_row(*r) for r in rows)
                    or "<li>no HTTP servers found</li>")
        except Exception as e:
            body = (f"<li class=warn>{cfg.mode} mode failed: "
                    f"{html.escape(f'{type(e).__name__}: {e}')}</li>")
        h = html.escape(host)
        page = (f"<!doctype html><title>servers on {h}</title>{STYLE}"
                f"<h1>HTTP servers on {h} <small>{cfg.mode} mode</small></h1>"
                f"<ul>{body}</ul>{SCRIPT}").encode()
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
    ap.add_argument("--groups", choices=["on", "off"], default=env("GROUPS", "on"))
    cfg = ap.parse_args()

    srv = ThreadingHTTPServer(("0.0.0.0", cfg.port), Handler)
    srv.cfg = cfg
    print(f"portindex ({cfg.mode} mode) on http://0.0.0.0:{cfg.port}/", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
