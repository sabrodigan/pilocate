"""Read a NetScout scan, keep the Raspberry Pis, and flash one so it can be seen."""

import json
import re
import socket
import subprocess
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from identify import is_raspberry_pi, normal_mac

USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def valid_ip(value):
    if not IP_RE.match(value or ""):
        return False
    return all(0 <= int(part) <= 255 for part in value.split("."))


def valid_user(value):
    return bool(USER_RE.match(value or ""))


class NetScout:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def latest(self):
        return self._json("GET", "/api/scans/latest")

    def scan(self, cidr):
        return self._json("POST", "/api/scans", {"cidr": cidr})

    def progress(self):
        return self._json("GET", "/api/scans/progress")

    def history(self):
        return self._json("GET", "/api/scans")

    def latest_diff(self):
        try:
            return self._json("GET", "/api/scans/latest-diff")
        except RuntimeError as error:
            if "two scans" in str(error):
                return None
            raise

    def _json(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        timeout = 180 if method == "POST" else 15
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            try:
                detail = json.loads(detail).get("error", detail)
            except json.JSONDecodeError:
                pass
            raise RuntimeError(detail or f"NetScout returned {error.code}") from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"NetScout at {self.base_url} did not answer") from error


def _ping(ip):
    subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def mac_for(ip):
    result = subprocess.run(
        ["ip", "neigh", "show", ip],
        capture_output=True,
        text=True,
        check=False,
    )
    for token in result.stdout.split():
        mac = normal_mac(token)
        if mac:
            return mac
    return ""


def ssh_open(ip, timeout=0.6):
    try:
        with socket.create_connection((ip, 22), timeout):
            return True
    except OSError:
        return False


def short_name(hostname):
    if not hostname:
        return ""
    return hostname.split(".")[0]


def _parse_time(value):
    if isinstance(value, datetime):
        return value
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def duration_seconds(started, finished):
    start = _parse_time(started)
    end = _parse_time(finished)
    if not start or not end:
        return None
    return max(0, int((end - start).total_seconds()))


def _host_labels(hosts, limit=6):
    labels = []
    for host in hosts or []:
        label = short_name(host.get("hostname") or "") or host.get("ip") or ""
        if label:
            labels.append(label)
        if len(labels) >= limit:
            break
    return labels


def summarize_scan(scan):
    hosts = scan.get("hosts") or []
    host_count = scan.get("hostCount")
    return {
        "cidr": scan.get("cidr") or "",
        "startedAt": scan.get("startedAt"),
        "finishedAt": scan.get("finishedAt"),
        "durationSeconds": duration_seconds(scan.get("startedAt"), scan.get("finishedAt")),
        "hostsUp": host_count if isinstance(host_count, int) else len(hosts),
        "withOpenPorts": sum(1 for host in hosts if host.get("openPorts")),
        "named": sum(1 for host in hosts if host.get("hostname")),
        "ports": list(scan.get("ports") or []),
    }


def summarize_diff(diff):
    added = diff.get("added") or []
    removed = diff.get("removed") or []
    changed = diff.get("changed") or []
    return {
        "added": len(added),
        "removed": len(removed),
        "changed": len(changed),
        "addedNames": _host_labels(added),
        "removedNames": _host_labels(removed),
        "changedNames": _host_labels(changed),
    }


def summarize_history(item):
    return {
        "cidr": item.get("cidr") or "",
        "startedAt": item.get("startedAt"),
        "finishedAt": item.get("finishedAt"),
        "durationSeconds": duration_seconds(item.get("startedAt"), item.get("finishedAt")),
        "hostsUp": item.get("hostCount") or 0,
    }


def network_report(scout):
    try:
        progress = scout.progress()
    except RuntimeError as error:
        return {"reachable": False, "error": str(error)}
    report = {
        "reachable": True,
        "progress": {
            "active": bool(progress.get("active")),
            "scanned": int(progress.get("scanned") or 0),
            "total": int(progress.get("total") or 0),
            "up": int(progress.get("up") or 0),
        },
    }
    try:
        report["latest"] = summarize_scan(scout.latest())
    except RuntimeError as error:
        report["latestError"] = str(error)
        return report
    try:
        diff = scout.latest_diff()
    except RuntimeError:
        diff = None
    report["changes"] = summarize_diff(diff) if diff else None
    try:
        history = scout.history() or []
    except RuntimeError:
        history = []
    report["history"] = [summarize_history(item) for item in history[:6]]
    return report


def find_pis(scan):
    hosts = [host for host in scan.get("hosts") or [] if host.get("status") == "up" and valid_ip(host.get("ip"))]
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda host: _ping(host["ip"]), hosts))
    found = []
    for host in hosts:
        mac = mac_for(host["ip"])
        if not is_raspberry_pi(host, mac):
            continue
        found.append(
            {
                "ip": host["ip"],
                "mac": mac,
                "hostname": short_name(host.get("hostname") or ""),
                "open_ports": list(host.get("openPorts") or []),
                "ssh_open": 22 in (host.get("openPorts") or []) or ssh_open(host["ip"]),
                "present": True,
            }
        )
    found.sort(key=lambda item: [int(part) for part in item["ip"].split(".")])
    return found
