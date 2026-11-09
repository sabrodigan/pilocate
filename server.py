#!/usr/bin/env python3
"""Find the Raspberry Pis on the house network and flash one so you can see which it is."""

import json
import os
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from pymongo import MongoClient, ReturnDocument

from access import AuthFailed, flash, install_key, key_status, update_ssh_config
from locate import NetScout, find_pis, network_report, valid_ip, valid_user

NETSCOUT_URL = os.environ.get("NETSCOUT_URL", "http://127.0.0.1:8092")
SCAN_CIDR = os.environ.get("SCAN_CIDR", "192.168.1.0/24")
DEFAULT_USER = os.environ.get("PI_SSH_USER", "pi")
WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def utcnow():
    return datetime.now(timezone.utc)


def _password(body):
    value = body.get("password") if isinstance(body, dict) else None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 128 or "\n" in value or "\r" in value:
        return None
    return value


def source_line():
    if "127.0.0.1" in NETSCOUT_URL or "localhost" in NETSCOUT_URL:
        return "Scans come from the NetScout on this computer. 192.168.1.200 did not answer."
    return f"Scans come from NetScout at {NETSCOUT_URL}."


class Store:
    def __init__(self, uri):
        client = MongoClient(uri, serverSelectionTimeoutMS=4000)
        self.pis = client["pilocate"]["pis"]
        self.pis.create_index("ip")
        self.pis.create_index("mac")

    def remember(self, found, scan):
        seen = utcnow()
        scan_id = str(scan.get("id") or "")
        finished = scan.get("finishedAt")
        found_ips = {item["ip"] for item in found}
        for item in found:
            previous = self._by_mac_or_ip(item["mac"], item["ip"])
            doc = {
                "ip": item["ip"],
                "mac": item["mac"],
                "hostname": item["hostname"],
                "open_ports": item["open_ports"],
                "ssh_open": item["ssh_open"],
                "present": True,
                "ssh_user": (previous or {}).get("ssh_user") or DEFAULT_USER,
                "place": (previous or {}).get("place") or "",
                "key_installed": bool((previous or {}).get("key_installed")),
                "last_seen": seen,
                "scan_id": scan_id,
                "scan_finished": finished,
            }
            if previous and previous.get("_id") not in (item["mac"], None):
                self.pis.delete_one({"_id": previous["_id"]})
            key = item["mac"] or f"ip:{item['ip']}"
            self.pis.replace_one({"_id": key}, {**doc, "_id": key}, upsert=True)
        if found_ips:
            self.pis.update_many({"ip": {"$nin": list(found_ips)}}, {"$set": {"present": False, "ssh_open": False}})
        return self.list_pis()

    def list_pis(self):
        docs = []
        for doc in self.pis.find().sort("ip", 1):
            doc["id"] = str(doc.pop("_id"))
            if isinstance(doc.get("last_seen"), datetime):
                doc["last_seen"] = doc["last_seen"].isoformat()
            docs.append(doc)
        docs.sort(key=lambda doc: [int(part) for part in doc["ip"].split(".")] if valid_ip(doc.get("ip", "")) else [])
        return docs

    def get_by_ip(self, ip):
        doc = self.pis.find_one({"ip": ip})
        return doc

    def update(self, ip, fields):
        allowed = {}
        if "ssh_user" in fields:
            if not valid_user(fields["ssh_user"]):
                raise ValueError("The login name is not usable.")
            allowed["ssh_user"] = fields["ssh_user"]
        if "place" in fields:
            allowed["place"] = str(fields["place"])[:80]
        if not allowed:
            return None
        result = self.pis.find_one_and_update(
            {"ip": ip}, {"$set": allowed}, return_document=ReturnDocument.AFTER
        )
        return result

    def mark_key(self, ip, installed):
        self.pis.update_one({"ip": ip}, {"$set": {"key_installed": bool(installed)}})

    def _by_mac_or_ip(self, mac, ip):
        if mac:
            found = self.pis.find_one({"_id": mac})
            if found:
                return found
        return self.pis.find_one({"ip": ip})


def make_handler(store, scout):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/api/pis":
                self._json(200, {
                    "pis": store.list_pis(),
                    "source": source_line(),
                    "cidr": SCAN_CIDR,
                    "key": key_status(),
                    "network": network_report(scout),
                })
                return
            if path == "/api/network":
                self._json(200, network_report(scout))
                return
            self._file(path)

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/api/refresh":
                self._refresh(run_scan=False)
                return
            if path == "/api/scan":
                self._refresh(run_scan=True)
                return
            if path == "/api/find":
                self._find()
                return
            if path == "/api/keys":
                self._keys()
                return
            self._json(404, {"error": "Not found"})

        def do_PATCH(self):
            path = urlparse(self.path).path
            prefix = "/api/pis/"
            if not path.startswith(prefix):
                self._json(404, {"error": "Not found"})
                return
            ip = path[len(prefix):]
            if not valid_ip(ip):
                self._json(400, {"error": "That is not a Pi address."})
                return
            try:
                updated = store.update(ip, self._body())
            except ValueError as error:
                self._json(400, {"error": str(error)})
                return
            if updated is None:
                self._json(404, {"error": "That Pi is not in the saved list. Refresh the scan first."})
                return
            self._json(200, {"pis": store.list_pis(), "source": source_line(), "saved": {"ip": ip, "place": updated.get("place") or ""}})

        def _refresh(self, run_scan):
            try:
                scan = scout.scan(SCAN_CIDR) if run_scan else scout.latest()
                found = find_pis(scan)
                pis = store.remember(found, scan)
            except RuntimeError as error:
                self._json(502, {"error": str(error)})
                return
            self._publish_ssh_config()
            self._json(200, {
                "pis": pis,
                "found": len(found),
                "finished": scan.get("finishedAt"),
                "cidr": scan.get("cidr"),
                "source": source_line(),
                "key": key_status(),
                "network": network_report(scout),
            })

        def _find(self):
            body = self._body()
            ip = body.get("ip") or ""
            if not valid_ip(ip):
                self._json(400, {"error": "Choose a Pi from the list."})
                return
            record = store.get_by_ip(ip)
            if not record:
                self._json(404, {"error": "That Pi is not in the saved list. Refresh the scan first."})
                return
            user = body.get("sshUser") or record.get("ssh_user") or DEFAULT_USER
            if not valid_user(user):
                self._json(400, {"error": "The login name is not usable."})
                return
            try:
                result = flash(ip, user, _password(body))
            except (AuthFailed, RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as error:
                if getattr(error, "key_installed", False):
                    store.mark_key(ip, True)
                self._json(502, {"error": str(error)})
                return
            self._remember_login(ip, result)
            self._publish_ssh_config()
            self._json(200, {"ok": True, "message": result["message"], "pis": store.list_pis(), "key": key_status()})

        def _keys(self):
            body = self._body()
            password = _password(body)
            results = []
            for record in store.list_pis():
                if not record.get("present"):
                    continue
                user = record.get("ssh_user") or DEFAULT_USER
                ip = record.get("ip")
                try:
                    result = install_key(ip, user, password)
                    self._remember_login(ip, result)
                    results.append({"ip": ip, "hostname": record.get("hostname") or ip, "ok": True, "message": result["message"]})
                except (AuthFailed, RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as error:
                    results.append({"ip": ip, "hostname": record.get("hostname") or ip, "ok": False, "message": str(error)})
            self._publish_ssh_config()
            ready = sum(1 for item in results if item["ok"])
            self._json(200, {
                "ok": ready == len(results) and len(results) > 0,
                "ready": ready,
                "results": results,
                "pis": store.list_pis(),
                "key": key_status(),
                "message": f"The 1Password key is on {ready} of {len(results)} Pis.",
            })

        def _remember_login(self, ip, result):
            store.mark_key(ip, result.get("key_installed"))
            user = result.get("ssh_user")
            if not user:
                return
            try:
                store.update(ip, {"ssh_user": user})
            except ValueError:
                return

        def _publish_ssh_config(self):
            try:
                update_ssh_config(store.list_pis())
            except OSError:
                return

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > 8192:
                return {}
            raw = self.rfile.read(length) if length else b"{}"
            try:
                return json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                return {}

        def _json(self, status, payload):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _file(self, path):
            name = "index.html" if path in ("", "/") else path.lstrip("/")
            if ".." in name:
                self.send_error(404)
                return
            full = os.path.join(WEB, name)
            if not os.path.isfile(full):
                self.send_error(404)
                return
            kind = "text/html"
            if name.endswith(".js"):
                kind = "text/javascript"
            elif name.endswith(".css"):
                kind = "text/css"
            elif name.endswith(".svg"):
                kind = "image/svg+xml"
            data = open(full, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            return

    return Handler


def main():
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    store = Store(uri)
    scout = NetScout(NETSCOUT_URL)
    host, _, port = os.environ.get("LISTEN_ADDR", "0.0.0.0:8094").rpartition(":")
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port)), make_handler(store, scout))
    print(f"pilocate listening on http://{host or '0.0.0.0'}:{port}", flush=True)
    print(f"NetScout scans from {NETSCOUT_URL}", flush=True)
    try:
        status = key_status()
        update_ssh_config(store.list_pis())
        if status.get("ready"):
            print(f"SSH key for the Pis: {status.get('comment')} {status.get('fingerprint')}", flush=True)
        else:
            print(f"SSH key setup: {status.get('error')}", flush=True)
    except OSError as error:
        print(f"SSH config was not written: {error}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
