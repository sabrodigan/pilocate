"""Count packages waiting to be upgraded on a Pi, once a day at 04:00."""

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from access import _without_secrets, agent_sock, login_attempts, pub_path

SUMMARY = re.compile(r"(\d+) upgraded, (\d+) newly installed")
CHECK_HOUR = 4

REPORT = r"""
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
if apt-get update -qq >/dev/null 2>&1; then
  echo "update_ok yes"
else
  echo "update_ok no"
fi
apt-get -s upgrade 2>/dev/null || true
"""


def due_at(now, hour=CHECK_HOUR):
    due = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if now < due:
        due -= timedelta(days=1)
    return due


def next_check(now, hour=CHECK_HOUR):
    nxt = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return nxt


def check_is_stale(checked_at, now, hour=CHECK_HOUR):
    if not checked_at:
        return True
    try:
        stamp = datetime.fromisoformat(str(checked_at).replace("Z", "+00:00"))
    except ValueError:
        return True
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=now.tzinfo)
    return stamp < due_at(now, hour)


def parse_updates(text):
    upgraded = newly = None
    lists_refreshed = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line == "update_ok yes":
            lists_refreshed = True
        elif line == "update_ok no":
            lists_refreshed = False
        match = SUMMARY.search(line)
        if match:
            upgraded = int(match.group(1))
            newly = int(match.group(2))
    if upgraded is None:
        raise RuntimeError("The Pi did not report an upgrade count.")
    return {
        "count": upgraded + newly,
        "upgraded": upgraded,
        "new": newly,
        "lists_refreshed": lists_refreshed,
    }


def _ssh(user, ip, remote, data):
    return subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "IdentitiesOnly=yes",
            "-o", f"IdentityAgent={agent_sock()}",
            "-o", f"IdentityFile={pub_path()}",
            f"{user}@{ip}",
            remote,
        ],
        input=data,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


def _parsed(result):
    if result.returncode != 0:
        detail = " ".join(((result.stderr or "") + " " + (result.stdout or "")).split())
        return None, detail
    try:
        return parse_updates(result.stdout), ""
    except RuntimeError as error:
        return None, str(error)


def count_updates(ip, user):
    user = user or "pi"
    direct = _ssh(user, ip, "sudo -n bash -s", REPORT)
    found, detail = _parsed(direct)
    if found:
        return found
    if direct.returncode == 0:
        raise RuntimeError(detail or "The Pi did not report an upgrade count.")
    secrets = []
    for candidate, secret in login_attempts(user, None):
        if candidate == user and secret not in secrets:
            secrets.append(secret)
    for _candidate, secret in login_attempts(user, None):
        if secret not in secrets:
            secrets.append(secret)
    last = f"Reached {user}, but sudo refused the saved password."
    secret_text = secrets
    for secret in secrets:
        result = _ssh(user, ip, "sudo -S -p '' bash -s", secret + "\n" + REPORT)
        found, detail = _parsed(result)
        if found:
            return found
        if result.returncode == 0:
            raise RuntimeError(detail or "The Pi did not report an upgrade count.")
        cleaned = _without_secrets(detail, secret_text)
        if cleaned and "Sorry" not in cleaned and "password" not in cleaned.lower():
            last = cleaned
    raise RuntimeError(last)


def readable_failure(detail, ip):
    text = " ".join(str(detail or "").split())
    if any(phrase in text for phrase in ("No route to host", "Connection timed out", "Connection refused", "timed out")):
        return f"{ip} did not answer, so the package count was not read."
    return (text or f"{ip} did not report an upgrade count.")[:300]


def collect_updates(store, records):
    targets = [record for record in records if record.get("ip")]

    def one(record):
        ip = record["ip"]
        user = record.get("ssh_user") or "pi"
        try:
            report = count_updates(ip, user)
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
            return ip, None, str(error)
        report["checked_at"] = datetime.now().astimezone().isoformat()
        return ip, report, ""

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(one, targets))
    for ip, report, error in results:
        name = next((record.get("hostname") or ip for record in targets if record.get("ip") == ip), ip)
        if report:
            store.save_updates(ip, report)
            print(f"{name}: {report['upgraded']} to upgrade, {report['new']} new", flush=True)
        else:
            message = readable_failure(error, ip)
            store.note_updates_error(ip, message)
            print(f"{name}: {message}", flush=True)


def watch_updates(store, stop):
    while not stop.is_set():
        now = datetime.now().astimezone()
        try:
            records = store.list_pis()
        except Exception as error:
            print(f"Package check could not read the Pi list: {error}", flush=True)
            stop.wait(60)
            continue
        pending = [
            record for record in records
            if record.get("ip") and check_is_stale((record.get("updates") or {}).get("checked_at"), now)
        ]
        if pending:
            print(f"Checking package updates on {len(pending)} Pis", flush=True)
            try:
                collect_updates(store, pending)
            except Exception as error:
                print(f"Package check stopped: {error}", flush=True)
        wait = max(1, (next_check(datetime.now().astimezone()) - datetime.now().astimezone()).total_seconds())
        print(f"Next package check at {next_check(datetime.now().astimezone()).strftime('%Y-%m-%d %H:%M %Z')}", flush=True)
        stop.wait(wait)
