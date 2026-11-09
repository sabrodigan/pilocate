"""Sign in to a Pi, install one 1Password key, and flash its activity light."""

import os
import re
import shlex
import subprocess
from pathlib import Path

import paramiko

PUBKEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+(?: .+)?$")
BEGIN = "# pilocate begin"
END = "# pilocate end"

BLINK = r"""
set -u
led=""
for cand in /sys/class/leds/ACT /sys/class/leds/led0 /sys/class/leds/PWR; do
  if [ -d "$cand" ]; then
    led=$cand
    break
  fi
done
if [ -z "$led" ]; then
  echo "This Pi has no activity LED that this app can see."
  exit 1
fi
trigger=$(sed -n 's/.*\[\([^]]*\)\].*/\1/p' "$led/trigger" | head -n 1)
write_led() {
  if [ -w "$1" ]; then
    printf '%s' "$2" > "$1"
    return
  fi
  if [ "$(id -u)" -eq 0 ]; then
    printf '%s' "$2" > "$1"
    return
  fi
  printf '%s' "$2" | sudo -n tee "$1" >/dev/null
}
if ! write_led "$led/trigger" none; then
  echo "Reached the Pi, but the LED needs sudo for this user."
  exit 1
fi
i=0
while [ "$i" -lt 16 ]; do
  write_led "$led/brightness" 1
  sleep 0.2
  write_led "$led/brightness" 0
  sleep 0.2
  i=$((i + 1))
done
write_led "$led/trigger" "${trigger:-mmc0}"
echo "Flashed the activity light."
"""


class AuthFailed(RuntimeError):
    pass


class NeedsSudo(RuntimeError):
    pass


def agent_sock():
    return os.path.expanduser(os.environ.get("PI_SSH_AGENT", "~/.1password/agent.sock"))


def pub_path():
    return os.path.expanduser(os.environ.get("PI_SSH_PUB", "~/.ssh/pilocate_pi.pub"))


def default_password():
    return os.environ.get("PI_SSH_PASSWORD", "pi")


def logins_path():
    return Path(os.path.expanduser(os.environ.get("PI_SSH_LOGINS", "~/.config/pilocate/logins")))


def parse_logins(text):
    found = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " " in line:
            user, password = line.split(None, 1)
        elif ":" in line:
            user, password = line.split(":", 1)
        else:
            continue
        user = user.strip()
        password = password.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", user) and password and "\n" not in password and "\r" not in password:
            found.append((user, password))
    return found


def saved_logins():
    path = logins_path()
    if not path.is_file():
        return [("pi", default_password())]
    return parse_logins(path.read_text()) or [("pi", default_password())]


def order_attempts(user, password, saved):
    ordered = []

    def add(candidate, secret):
        if candidate and secret and (candidate, secret) not in ordered:
            ordered.append((candidate, secret))

    if password:
        add(user or "pi", password)
    for candidate, secret in saved:
        add(candidate, secret)
    if not ordered:
        add("pi", default_password())
    return ordered


def login_attempts(user, password):
    return order_attempts(user, password, saved_logins())


def login_users(user=None):
    names = []
    if user:
        names.append(user)
    for candidate, _secret in saved_logins():
        if candidate not in names:
            names.append(candidate)
    return names or ["pi"]


def parse_agent_line(line):
    parts = (line or "").strip().split()
    if len(parts) < 2 or parts[0] not in ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"):
        return None
    comment = " ".join(parts[2:])
    cleaned = f"{parts[0]} {parts[1]}" + (f" {comment}" if comment else "")
    if not PUBKEY_RE.match(cleaned):
        return None
    return {"type": parts[0], "comment": comment, "line": cleaned}


def choose_key(keys, prefer=None):
    prefer = (os.environ.get("PI_SSH_KEY_COMMENT", "termius") if prefer is None else prefer).lower()
    if prefer:
        for key in keys:
            if prefer in key["comment"].lower():
                return key
    for key in keys:
        if "github" in key["comment"].lower():
            continue
        if key["type"] == "ssh-ed25519":
            return key
    for key in keys:
        if "github" not in key["comment"].lower():
            return key
    raise RuntimeError("The 1Password SSH agent has no key to install on the Pis.")


def load_agent_keys(sock=None):
    sock = sock or agent_sock()
    if not os.path.exists(sock):
        raise RuntimeError("The 1Password SSH agent is not running. Unlock 1Password and turn on the SSH agent.")
    env = os.environ.copy()
    env["SSH_AUTH_SOCK"] = sock
    result = subprocess.run(
        ["ssh-add", "-L"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=8,
    )
    keys = []
    for line in (result.stdout or "").splitlines():
        parsed = parse_agent_line(line)
        if parsed:
            keys.append(parsed)
    if not keys:
        detail = (result.stderr or "").strip()
        raise RuntimeError(detail or "The 1Password SSH agent did not offer a public key.")
    return keys


def selected_key():
    key = choose_key(load_agent_keys())
    path = Path(pub_path())
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(key["line"] + "\n")
    path.chmod(0o644)
    return key


def key_status():
    try:
        key = selected_key()
    except (RuntimeError, OSError) as error:
        return {"ready": False, "error": str(error)}
    listed = subprocess.run(
        ["ssh-keygen", "-lf", pub_path()],
        capture_output=True,
        text=True,
        check=False,
    )
    fingerprint = ""
    for token in (listed.stdout or "").split():
        if token.startswith("SHA256:"):
            fingerprint = token
            break
    return {
        "ready": True,
        "comment": key["comment"] or key["type"],
        "fingerprint": fingerprint,
    }


def render_ssh_config(records, pub, agent):
    grouped = {}
    order = []
    safe_name = re.compile(r"^[A-Za-z0-9_.:-]+$")
    safe_user = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
    for record in records:
        user = record.get("ssh_user") or "pi"
        if not safe_user.match(user):
            continue
        if user not in grouped:
            grouped[user] = []
            order.append(user)
        for name in (record.get("ip"), record.get("hostname")):
            if name and safe_name.match(name) and name not in grouped[user]:
                grouped[user].append(name)
    lines = [BEGIN]
    for user in order:
        names = grouped[user]
        if not names:
            continue
        lines.append("Host " + " ".join(names))
        lines.append(f"  User {user}")
        lines.append(f"  IdentityAgent {agent}")
        lines.append(f"  IdentityFile {pub}")
        lines.append("  IdentitiesOnly yes")
    lines.append(END)
    return "\n".join(lines) + "\n"


def splice_ssh_config(existing, block):
    text = existing or ""
    if BEGIN in text and END in text:
        pre, rest = text.split(BEGIN, 1)
        _, post = rest.split(END, 1)
        text = pre.rstrip() + "\n" + post.lstrip("\n")
    text = text.rstrip() + "\n\n" + block
    return text


def update_ssh_config(records, config_path=None):
    path = Path(config_path or os.path.expanduser("~/.ssh/config"))
    path.parent.mkdir(mode=0o700, exist_ok=True)
    existing = path.read_text() if path.exists() else ""
    block = render_ssh_config(records, pub_path(), agent_sock())
    path.write_text(splice_ssh_config(existing, block))
    path.chmod(0o600)
    return block


def _ssh_base(user, ip):
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "IdentitiesOnly=yes",
        "-o", f"IdentityAgent={agent_sock()}",
        "-o", f"IdentityFile={pub_path()}",
        f"{user}@{ip}",
    ]


def _without_secrets(text, secrets):
    cleaned = text or ""
    for secret in secrets:
        if secret:
            cleaned = cleaned.replace(secret, "")
    return " ".join(cleaned.split())


def sudo_bash_command():
    # One remote command. An empty separate argument is dropped by ssh, and
    # sudo then treats the next word as the prompt instead of the shell.
    return "sudo -S -p '' bash -s"


def blink_with_key_sudo(ip, user, secrets):
    last = f"Reached {user}, but the LED needs sudo and the saved password was refused."
    for secret in secrets:
        result = subprocess.run(
            [*_ssh_base(user, ip), sudo_bash_command()],
            input=secret + "\n" + BLINK,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        message = (result.stdout or "").strip()
        detail = _without_secrets(result.stderr or message, secrets)
        if result.returncode == 0 and "Flashed" in message:
            return message
        if detail and "Sorry" not in detail and "password" not in detail.lower():
            last = detail
    raise RuntimeError(last)


def blink_with_key(ip, user):
    result = subprocess.run(
        [*_ssh_base(user, ip), "bash", "-s"],
        input=BLINK,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    message = (result.stdout or result.stderr or "").strip()
    combined = f"{result.stderr or ''}\n{message}"
    if result.returncode != 0:
        if "Permission denied" in combined or "Too many authentication failures" in combined:
            raise AuthFailed(f"The Pi refused the 1Password key for {user}.")
        if "LED needs sudo" in message:
            raise NeedsSudo(message)
        raise RuntimeError(message or "The Pi did not flash its light.")
    return message or "Flashed the activity light."


def _connect(ip, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip,
            username=user,
            password=password,
            timeout=8,
            banner_timeout=8,
            auth_timeout=12,
            allow_agent=False,
            look_for_keys=False,
        )
    except paramiko.AuthenticationException as error:
        client.close()
        raise AuthFailed(f"The Pi refused the password for {user}.") from error
    except (paramiko.SSHException, OSError) as error:
        client.close()
        raise RuntimeError(f"{user}@{ip} did not accept the password login.") from error
    return client


def _run(client, script, stdin_prefix=""):
    stdin, stdout, stderr = client.exec_command("bash -s", timeout=30)
    stdin.write(stdin_prefix + script)
    stdin.channel.shutdown_write()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return code, (out or err).strip()


def _sudo_is_open(client):
    stdin, stdout, stderr = client.exec_command("sudo -n true", timeout=10)
    stdin.close()
    return stdout.channel.recv_exit_status() == 0


def _blink_with_sudo_password(client, password):
    stdin, stdout, stderr = client.exec_command("sudo -S -p '' bash -s", timeout=30)
    stdin.write(password + "\n" + BLINK)
    stdin.channel.shutdown_write()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    message = (out or err).strip()
    if code != 0:
        raise RuntimeError(message or "The Pi did not flash its light.")
    return message or "Flashed the activity light."


def install_authorized_key(client, pubkey_line):
    if not PUBKEY_RE.match(pubkey_line):
        raise RuntimeError("The 1Password public key is not in a form this app can install.")
    quoted = shlex.quote(pubkey_line)
    script = f"""
set -eu
umask 077
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 700 "$HOME/.ssh"
chmod 600 "$HOME/.ssh/authorized_keys"
grep -qxF {quoted} "$HOME/.ssh/authorized_keys" || printf '%s\\n' {quoted} >> "$HOME/.ssh/authorized_keys"
echo "Installed the key."
"""
    code, message = _run(client, script)
    if code != 0:
        raise RuntimeError(message or "The key was not added to the Pi.")
    return message


def _finish_on_client(client, password, pubkey_line, blink):
    install_authorized_key(client, pubkey_line)
    if not blink:
        return "Installed the key."
    if _sudo_is_open(client):
        code, message = _run(client, BLINK)
        if code != 0:
            raise RuntimeError(message or "The Pi did not flash its light.")
        return message or "Flashed the activity light."
    return _blink_with_sudo_password(client, password)


def connect_with_logins(ip, user, password):
    last = AuthFailed("None of the saved logins were accepted.")
    for candidate, secret in login_attempts(user, password):
        try:
            return _connect(ip, candidate, secret), candidate, secret
        except AuthFailed as error:
            last = error
    raise AuthFailed("None of the saved logins were accepted.") from last


def accept_key(ip, user=None):
    for candidate in login_users(user):
        try:
            result = subprocess.run(
                [*_ssh_base(candidate, ip), "echo", "key-ok"],
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0 and "key-ok" in (result.stdout or ""):
            return candidate
    return ""


def flash(ip, user, password=None):
    key = selected_key()
    for candidate in login_users(user):
        try:
            message = blink_with_key(ip, candidate)
            return {
                "message": f"{message} This Pi already accepts the 1Password key {key['comment']} for {candidate}.",
                "key_installed": True,
                "ssh_user": candidate,
            }
        except NeedsSudo:
            secrets = [secret for candidate_user, secret in login_attempts(user, password) if candidate_user == candidate]
            try:
                message = blink_with_key_sudo(ip, candidate, secrets)
            except RuntimeError:
                continue
            return {
                "message": f"{message} Signed in as {candidate} with the 1Password key.",
                "key_installed": True,
                "ssh_user": candidate,
            }
        except AuthFailed:
            continue
    client, used, secret = connect_with_logins(ip, user, password)
    try:
        message = _finish_on_client(client, secret, key["line"], blink=True)
    finally:
        client.close()
    return {
        "message": f"Installed the 1Password key {key['comment']} for {used} and flashed the activity light.",
        "key_installed": True,
        "ssh_user": used,
        "detail": message,
    }


def install_key(ip, user, password=None):
    key = selected_key()
    found = accept_key(ip, user)
    if found:
        return {
            "message": f"{found}@{ip} already accepts the 1Password key {key['comment']}.",
            "key_installed": True,
            "ssh_user": found,
        }
    client, used, secret = connect_with_logins(ip, user, password)
    try:
        _finish_on_client(client, secret, key["line"], blink=False)
    finally:
        client.close()
    return {
        "message": f"Installed the 1Password key {key['comment']} on {used}@{ip}.",
        "key_installed": True,
        "ssh_user": used,
    }
