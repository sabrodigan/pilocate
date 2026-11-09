# pilocate

Finds the Raspberry Pis on `192.168.1.0/24` and flashes the activity light on the one you are looking at.

It does not scan the network itself. It reads a scan from NetScout (`GET /api/scans/latest`) and can ask NetScout to run another (`POST /api/scans`). The top of the page shows NetScout's live progress while a scan is running, then the finished counts: hosts up, hosts with an open port, named hosts, and what appeared, disappeared, or changed ports since the previous scan. A host is kept when its name looks like a Pi (`raspberry`, `ras-5`, `ras4`) or its hardware address is a Raspberry Pi prefix. Each Pi is stored in MongoDB database `pilocate`, collection `pis`, including a place name and the login used to flash the light.

Flashing signs in with one public key from the 1Password SSH agent. The key it chooses is the one whose comment contains `termius` (`termius_gcp_key`), which is the same key Termius already holds. Until that key is on a Pi, the app signs in as `pi` with `PI_SSH_PASSWORD` and adds the public key to `~/.ssh/authorized_keys`. It also writes a marked block in `~/.ssh/config` so this computer offers only that key to those Pis.

## Run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
```

Open <http://127.0.0.1:8094> on this computer. Other devices on the house network use this computer's `192.168.1` address on port 8094. The firewall has to allow it:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8094 proto tcp comment 'pilocate'
```

| Variable | Default | Purpose |
|---|---|---|
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB |
| `NETSCOUT_URL` | `http://127.0.0.1:8092` | NetScout to read and run scans |
| `SCAN_CIDR` | `192.168.1.0/24` | Network passed to NetScout when you scan |
| `LISTEN_ADDR` | `0.0.0.0:8094` | Where this app listens |
| `PI_SSH_USER` | `pi` | Login used the first time a Pi is saved |
| `PI_SSH_PASSWORD` | `pi` | Used when `~/.config/pilocate/logins` is missing |
| `PI_SSH_LOGINS` | `~/.config/pilocate/logins` | Extra logins, one `user password` per line. Tried when the key is not on that Pi yet |
| `PI_SSH_KEY_COMMENT` | `termius` | Which 1Password agent key to install. Matched against the key comment |
| `PI_SSH_AGENT` | `~/.1password/agent.sock` | 1Password SSH agent socket |
| `PI_SSH_PUB` | `~/.ssh/pilocate_pi.pub` | Public half written here so SSH and Termius can select that one key |
