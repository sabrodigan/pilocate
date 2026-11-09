"""Read a Pi's board, processor, memory, clock, and kernel over SSH."""

import subprocess

from access import agent_sock, pub_path

REPORT = r"""
board=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || true)
cpu=$(awk -F: 'tolower($1) ~ /^model name$/ { gsub(/^[ \t]+/, "", $2); if ($2 != "" && $2 != "-") { print $2; exit } }' /proc/cpuinfo)
if [ -z "$cpu" ]; then
  cpu=$(lscpu 2>/dev/null | awk -F: 'tolower($1) ~ /^model name$/ { gsub(/^[ \t]+/, "", $2); print $2; exit }')
fi
cores=$(nproc 2>/dev/null || true)
ram=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo)
clock=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || true)
printf '%s\n' "uname $(uname -a)" "board ${board}" "cpu ${cpu}" "cores ${cores}" "ram_kb ${ram}" "clock_khz ${clock}"
"""

FIELDS = {"uname", "board", "cpu", "cores", "ram_kb", "clock_khz"}
RAM_SIZES_GB = (1, 2, 4, 8, 16, 32)


def format_cpu(model, cores):
    model = (model or "").strip()
    if model == "-":
        model = ""
    count = ""
    try:
        number = int(str(cores).strip())
    except ValueError:
        number = 0
    if number > 0:
        count = "1 core" if number == 1 else f"{number} cores"
    if model and count:
        return f"{model}, {count}"
    return model or count


def format_ram(kb_text):
    try:
        kb = int(str(kb_text).strip())
    except ValueError:
        return ""
    if kb <= 0:
        return ""
    gib = kb / (1024 * 1024)
    for size in RAM_SIZES_GB:
        if abs(gib - size) / size <= 0.12:
            return f"{size} GB"
    return f"{gib:.1f} GB"


def format_clock(khz_text):
    try:
        khz = int(str(khz_text).strip())
    except ValueError:
        return ""
    if khz <= 0:
        return ""
    mhz = khz / 1000
    if mhz >= 1000:
        text = f"{mhz / 1000:.1f}".rstrip("0").rstrip(".")
        return f"{text} GHz"
    return f"{mhz:.0f} MHz"


def parse_hardware(text):
    found = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if " " not in line:
            continue
        key, value = line.split(" ", 1)
        if key in FIELDS:
            found[key] = value.strip()
    uname = found.get("uname") or ""
    board = found.get("board") or ""
    if not uname and not board:
        raise RuntimeError("The Pi did not report a board or a kernel.")
    return {
        "uname": uname,
        "board": board,
        "cpu": format_cpu(found.get("cpu") or "", found.get("cores") or ""),
        "ram": format_ram(found.get("ram_kb") or ""),
        "clock": format_clock(found.get("clock_khz") or ""),
    }


def read_hardware(ip, user):
    user = user or "pi"
    result = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "IdentitiesOnly=yes",
            "-o", f"IdentityAgent={agent_sock()}",
            "-o", f"IdentityFile={pub_path()}",
            f"{user}@{ip}",
            REPORT,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        detail = " ".join(((result.stderr or "") + " " + (result.stdout or "")).split())
        if "Permission denied" in detail:
            raise RuntimeError(f"{user}@{ip} refused the SSH key.")
        raise RuntimeError(detail[:300] or f"{user}@{ip} did not report its hardware.")
    return parse_hardware(result.stdout)
