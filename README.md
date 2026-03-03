# Moat

**Security hardening wizard for self-hosted AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#)
[![GitHub release](https://img.shields.io/github/v/release/matsulinks/moat)](https://github.com/matsulinks/moat/releases)

---

Running an AI agent on your own hardware is powerful — but the agent can read files, call APIs, and talk to the internet. **One misconfigured permission is all it takes.**

Moat detects your environment and generates a hardened security config in under 2 minutes. No YAML expertise needed.

```
curl -O https://raw.githubusercontent.com/matsulinks/moat/main/setup.py
python3 setup.py --web
```

Then open **http://localhost:8765** and follow the wizard.

---

## What Moat does

Moat scans your host and generates config files for up to 7 independent security layers:

| Layer | What it hardens | Generated file |
|---|---|---|
| 1 · Network isolation | Tailscale ACL + iptables blocks C2 traffic | `tailscale-acl.json`, `iptables-setup.sh` |
| 2 · Docker hardening | Drop capabilities, read-only root, no-new-privileges | `docker-compose.yml` |
| 3 · Auth & access control | API keys, rate limits, IP allowlist | `config.yaml` |
| 4 · Secrets management | Infisical self-hosted (optional, 8 GB+ RAM) | `infisical-compose.yml` |
| 5 · Skill & prompt defense | ClawHub blocklist + LLM-as-Judge (optional) | `config.yaml` |
| 6 · Runtime least-privilege | Default-deny tool permissions per agent role | `config.yaml` |
| 7 · Observability | Falco syscall rules + Prometheus alerts | `falco_rules.local.yaml`, `alerts.yaml` |

Moat **never installs anything**. It generates files — you apply them when you're ready.

---

## Works with

- **OpenClaw** — primary target
- **LangChain Agents**, **AutoGen**, **CrewAI**, **LlamaIndex Workflows** — Layer 1–4 apply to any Docker-based agent
- **Raspberry Pi 5** (8 GB) — fully tested
- Raspberry Pi 4, x86 Linux, macOS (Layer 1–6)

---

## Quick start

### Browser wizard (recommended)

```bash
curl -O https://raw.githubusercontent.com/matsulinks/moat/main/setup.py
python3 setup.py --web
# Opens http://localhost:8765
```

### Terminal mode

```bash
python3 setup.py
```

### Options

```
python3 setup.py --web       # Browser UI on localhost:8765
python3 setup.py --cli       # Terminal wizard (default)
python3 setup.py --update    # Self-update with SHA256 verification
python3 setup.py --help      # Usage
```

**Zero dependencies.** Runs on Python 3.8+ with stdlib only.

---

## Output

After running the wizard, all files land in `output/`:

```
output/
  docker-compose.yml        # Drop-in replacement for your current compose file
  config.yaml               # Auth + tool permissions + prompt defense settings
  tailscale-acl.json        # ACL rules with C2 egress blocks
  SETUP_GUIDE.md            # Step-by-step guide for your exact selection
  falco_rules.local.yaml    # (if Layer 7 selected)
  alerts.yaml               # (if Layer 7 selected)
  infisical-compose.yml     # (if Layer 4 selected)
```

---

## Security layers in detail

<details>
<summary><strong>Layer 1 — Network isolation</strong></summary>

Generates a Tailscale ACL that:
- Limits SSH access to your admin device only
- Blocks all outbound traffic except explicitly allowlisted domains
- Prevents agent-to-agent lateral movement within your network

Also generates `iptables-setup.sh` that blocks C2 callback patterns.
</details>

<details>
<summary><strong>Layer 2 — Docker hardening</strong></summary>

Drop-in `docker-compose.yml` that adds:
- `cap_drop: ALL` + only needed capabilities re-added
- `read_only: true` root filesystem
- `no-new-privileges: true`
- Isolated bridge network per agent
- Strict resource limits (CPU, memory, PID)
</details>

<details>
<summary><strong>Layer 3 — Auth & access control</strong></summary>

Generates `config.yaml` with:
- API key authentication (pre-filled with a placeholder, replace before use)
- IP allowlist (loopback + Tailscale subnet by default)
- Per-endpoint rate limiting
- Request logging
</details>

<details>
<summary><strong>Layer 6 — Runtime least-privilege</strong></summary>

The most impactful single layer. Every agent tool is **deny by default**. You explicitly allow:
- Which tools each role can call
- Which directories the agent can read/write
- Which external domains it can reach

If a compromised agent tries anything outside the allowlist, it's blocked and logged.
</details>

---

## Tested on

| Hardware | OS | RAM | Status |
|---|---|---|---|
| Raspberry Pi 5 | Debian 13 (trixie) | 8 GB | ✅ All layers |
| Raspberry Pi 4 | Raspberry Pi OS | 4 GB | ✅ Layers 1–3, 6 |
| x86 PC / VPS | Ubuntu 22.04 | 16 GB | ✅ All layers |
| macOS (M-series) | macOS 14+ | any | ✅ Layers 2–3, 5–6 |

---

## Why not just use [microsandbox](https://github.com/microsandbox/microsandbox)?

Microsandbox is great for sandboxing agent *code execution*. Moat hardens the *host* and *network* around the agent. They're complementary, not competing.

| | microsandbox | Moat |
|---|---|---|
| Sandboxes code execution | ✅ | ❌ |
| Hardens Docker config | ❌ | ✅ |
| Locks down network egress | ❌ | ✅ |
| Manages secrets | ❌ | ✅ |
| Restricts agent tool permissions | ❌ | ✅ |
| Setup wizard for non-experts | ❌ | ✅ |

---

## Roadmap

- [x] v0.1 — 7-layer wizard, browser UI, self-update
- [ ] v0.2 — Windows support, GUI installer
- [ ] v0.3 — Threat reporting (community intelligence feed)
- [ ] v1.0 — Paid: automatic rule updates based on community reports

---

## Contributing

Issues and PRs welcome. If you find a security gap that Moat should cover, open an issue.

---

## License

MIT — use freely, commercial use allowed.

> **Moat** — like the water surrounding a castle, it keeps threats out without getting in the way of the people inside.
