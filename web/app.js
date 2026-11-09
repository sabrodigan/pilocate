const cards = document.querySelector("#cards");
const status = document.querySelector("#status");
const source = document.querySelector("#source");
const keyLine = document.querySelector("#key-line");
const network = document.querySelector("#network");

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

async function request(url, options) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function passwordBody(extra) {
  const password = document.querySelector("#pi-password").value;
  return JSON.stringify(password ? { ...extra, password } : extra);
}

function stat(label, value) {
  const node = el("div", "stat");
  node.append(el("strong", "", value));
  node.append(el("span", "", label));
  return node;
}

function nameList(names, total) {
  if (!names || !names.length) return "";
  const extra = total - names.length;
  return extra > 0 ? ` (${names.join(", ")}, and ${extra} more)` : ` (${names.join(", ")})`;
}

function changeSentence(changes) {
  const parts = [];
  if (changes.added) parts.push(`${changes.added} appeared${nameList(changes.addedNames, changes.added)}`);
  if (changes.removed) parts.push(`${changes.removed} disappeared${nameList(changes.removedNames, changes.removed)}`);
  if (changes.changed) parts.push(`${changes.changed} changed ports${nameList(changes.changedNames, changes.changed)}`);
  if (!parts.length) return "Since the previous scan, the hosts that answered are the same.";
  return `Since the previous scan, ${parts.join(", ")}.`;
}

function renderNetwork(report) {
  network.replaceChildren();
  if (!report || report.reachable === false) {
    network.append(el("p", "network-line", report && report.error ? report.error : "NetScout did not answer."));
    return;
  }
  const progress = report.progress || {};
  const latest = report.latest;
  const tiles = el("div", "stats");
  if (progress.active) {
    const total = progress.total || 0;
    const scanned = progress.scanned || 0;
    const pct = total ? Math.round((scanned / total) * 100) : 0;
    tiles.append(stat("Scanning", `${scanned} of ${total}`));
    tiles.append(stat("Up so far", String(progress.up || 0)));
    tiles.append(stat("Checked", `${pct}%`));
    network.append(tiles);
    const bar = el("div", "bar");
    const fill = el("div", "bar-fill");
    fill.style.width = `${pct}%`;
    bar.append(fill);
    network.append(bar);
  } else if (latest) {
    tiles.append(stat("Hosts up", String(latest.hostsUp)));
    tiles.append(stat("With an open port", String(latest.withOpenPorts)));
    tiles.append(stat("Named", String(latest.named)));
    if (report.changes) tiles.append(stat("Since last scan", `+${report.changes.added}  −${report.changes.removed}`));
    network.append(tiles);
  }
  if (latest) {
    const when = latest.finishedAt ? new Date(latest.finishedAt).toLocaleString() : "";
    const took = latest.durationSeconds != null ? ` Took ${latest.durationSeconds}s.` : "";
    const ports = (latest.ports || []).join(", ");
    network.append(el("p", "network-line", `${latest.cidr} · ${latest.hostsUp} hosts up · finished ${when}.${took} Ports checked: ${ports}.`));
  } else if (report.latestError) {
    network.append(el("p", "network-line", report.latestError));
  }
  if (!progress.active && report.changes) network.append(el("p", "network-line", changeSentence(report.changes)));
  if (report.history && report.history.length) {
    const bits = report.history.slice(0, 5).map((item) => {
      const when = item.finishedAt ? new Date(item.finishedAt).toLocaleString() : "";
      return `${item.hostsUp} up${when ? ` at ${when}` : ""}`;
    });
    network.append(el("p", "network-line", `Recent scans: ${bits.join(" · ")}`));
  }
}

function render(data) {
  if (data.network) renderNetwork(data.network);
  if (data.source) source.textContent = data.source;
  if (data.key) {
    keyLine.textContent = data.key.ready
      ? `Tries the saved logins until the 1Password key ${data.key.comment} (${data.key.fingerprint}) is installed. Termius uses that same key.`
      : data.key.error;
  }
  cards.replaceChildren();
  const pis = data.pis || [];
  if (!pis.length) {
    cards.append(el("p", "muted", "No Raspberry Pis saved yet. Use the latest scan, or scan the network."));
    return;
  }
  for (const pi of pis) cards.append(card(pi));
}

function card(pi) {
  const node = el("article", "card");
  const top = el("div", "card-top");
  const heading = el("div");
  heading.append(el("h3", "", pi.hostname || pi.ip));
  heading.append(el("p", "muted", [pi.ip, pi.mac].filter(Boolean).join(" · ")));
  if (pi.place) heading.append(el("p", "place", pi.place));
  top.append(heading);
  const badges = el("div", "badges");
  badges.append(el("span", pi.present ? "badge" : "badge away", pi.present ? (pi.ssh_open ? "Reachable" : "Seen") : "Not in the last scan"));
  if (pi.key_installed) badges.append(el("span", "badge", "Key ready"));
  top.append(badges);
  node.append(top);
  if (pi.open_ports?.length) node.append(el("p", "muted", `Open ports ${pi.open_ports.join(", ")}`));
  const fields = el("div", "fields");
  fields.append(field("Where it lives", pi.place || "", (value) => save(pi, { place: value }), "Cupboard, loft, desk…"));
  fields.append(field("Login", pi.ssh_user || "pi", (value) => save(pi, { ssh_user: value })));
  node.append(fields);
  const actions = el("div", "row");
  const button = el("button", "", "Flash its light");
  button.addEventListener("click", () => find(pi, button));
  actions.append(button);
  node.append(actions);
  return node;
}

function field(labelText, value, onCommit, placeholder) {
  const label = el("label", "", labelText);
  const input = el("input");
  input.value = value;
  if (placeholder) input.placeholder = placeholder;
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") input.blur();
  });
  input.addEventListener("change", () => onCommit(input.value));
  label.append(input);
  return label;
}

async function save(pi, body) {
  try {
    const data = await request(`/api/pis/${pi.ip}`, { method: "PATCH", body: JSON.stringify(body) });
    render(data);
    const name = pi.hostname || pi.ip;
    if ("place" in body) {
      status.textContent = body.place
        ? `Saved “${body.place}” as where ${name} lives. NetScout shows that location too.`
        : `Cleared where ${name} lives.`;
    } else {
      status.textContent = `Saved the login for ${name}.`;
    }
  } catch (error) {
    status.textContent = error.message;
  }
}

async function find(pi, button) {
  button.disabled = true;
  status.textContent = `Flashing ${pi.hostname || pi.ip}…`;
  try {
    const result = await request("/api/find", {
      method: "POST",
      body: passwordBody({ ip: pi.ip }),
    });
    status.textContent = result.message;
    if (result.pis) render(result);
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function load(url, message) {
  status.textContent = message;
  document.querySelector("#refresh-btn").disabled = true;
  document.querySelector("#scan-btn").disabled = true;
  try {
    const data = await request(url, { method: "POST", body: "{}" });
    render(data);
    const when = data.finished ? ` Scan finished ${new Date(data.finished).toLocaleString()}.` : "";
    status.textContent = `Found ${data.found} Raspberry ${data.found === 1 ? "Pi" : "Pis"}.${when}`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    document.querySelector("#refresh-btn").disabled = false;
    document.querySelector("#scan-btn").disabled = false;
  }
}

document.querySelector("#refresh-btn").addEventListener("click", () => load("/api/refresh", "Reading the latest NetScout scan…"));
document.querySelector("#scan-btn").addEventListener("click", () => load("/api/scan", "Asking NetScout to scan 192.168.1.0/24…"));
document.querySelector("#keys-btn").addEventListener("click", async () => {
  const button = document.querySelector("#keys-btn");
  button.disabled = true;
  status.textContent = "Signing in to each Pi and installing the 1Password key…";
  try {
    const result = await request("/api/keys", { method: "POST", body: passwordBody({}) });
    render(result);
    const failed = (result.results || []).filter((item) => !item.ok);
    status.textContent = failed.length
      ? `${result.message} ${failed.map((item) => `${item.hostname}: ${item.message}`).join(" ")}`
      : result.message;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

request("/api/pis").then((data) => {
  render(data);
  if (!data.pis.length) load("/api/refresh", "Reading the latest NetScout scan…");
}).catch((error) => {
  status.textContent = error.message;
});

let networkBusy = false;
setInterval(() => {
  if (networkBusy) return;
  networkBusy = true;
  request("/api/network").then(renderNetwork).catch((error) => {
    renderNetwork({ reachable: false, error: error.message });
  }).finally(() => {
    networkBusy = false;
  });
}, 1000);
