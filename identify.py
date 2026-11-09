"""Decide which NetScout hosts are Raspberry Pis."""

import re

# Burned-in prefixes published for Raspberry Pi boards.
PI_OUIS = {
    "B8:27:EB",
    "DC:A6:32",
    "D8:3A:DD",
    "E4:5F:01",
    "28:CD:C1",
    "2C:CF:67",
}

# Hostnames this house already uses, plus the stock Raspberry Pi name.
PI_NAME = re.compile(r"(raspberry|raspi|\bras[\s-]?\d|\bras-|\bpi-\d)", re.IGNORECASE)


def normal_mac(value):
    if not value:
        return ""
    parts = re.split(r"[:-]", value.strip())
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return ""
    try:
        mac = ":".join(f"{int(part, 16):02X}" for part in parts)
    except ValueError:
        return ""
    return mac


def is_pi_mac(mac):
    mac = normal_mac(mac)
    return bool(mac) and mac[:8] in PI_OUIS


def is_pi_name(hostname):
    return bool(hostname) and bool(PI_NAME.search(hostname))


def is_raspberry_pi(host, mac=""):
    return is_pi_mac(mac) or is_pi_name(host.get("hostname") or "")
