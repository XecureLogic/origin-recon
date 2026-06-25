<p align="center">
  <img src="docs/origin-recon-cover.png" alt="Origin Recon" width="100%">
</p>

# Origin Recon

**Built by:** [XecureLogic](https://xecurelogic.com) — xecurelogic.com

A self-contained, locally-run DNS / origin / attacker-infrastructure recon tool.
Give it a domain and it does in one pass what normally takes a dozen browser tabs:
maps the DNS, classifies CDN edge vs. real origin, geo-locates the hosts, and flags
bulletproof ASNs and abuse.ch-confirmed known-bad infrastructure.

FastAPI backend + React/Vite/Tailwind frontend. Runs on your machine; API keys and
target data never leave your box.

## Screenshots

<p align="center">
  <img src="docs/screenshots/01-scan-interface.png" alt="Scan interface" width="900"><br>
  <em>The scan interface. Single or bulk mode, the live enrichment sources lit up across the top, and this session's scans as click-through chips.</em>
</p>

<p align="center">
  <img src="docs/screenshots/02-verdict.png" alt="Verdict" width="900"><br>
  <em>The headline verdict — MALICIOUS — with the reasoning, the defanged origin IOC, and one-click actions to check or report the URL to URLhaus.</em>
</p>

<p align="center">
  <img src="docs/screenshots/03-dns-graph.png" alt="DNS graph" width="900"><br>
  <em>The DNS graph — apex to record types to resolved hosts to networks, laid out so the structure reads in seconds.</em>
</p>

<p align="center">
  <img src="docs/screenshots/04-geolocation-risk.png" alt="Geolocation and risk" width="900"><br>
  <em>Resolved hosts placed on a real-projection world map, color-coded by role and risk, with a hosting breakdown and a risk summary.</em>
</p>

<p align="center">
  <img src="docs/screenshots/05-dns-records.png" alt="DNS records" width="900"><br>
  <em>The full DNS record tables — A, NS, SOA — each row enriched with ASN, the Team Cymru-announced origin, and a per-record risk flag.</em>
</p>

## What it does

For a target domain it performs **passive** OSINT recon and renders:

- **Headline verdict** — `MALICIOUS` / `SUSPICIOUS` / `NO MALICIOUS SIGNALS` / `INCONCLUSIVE`, with the reasoning stated plainly
- **DNS records** — A/AAAA/MX/NS/TXT/SOA, each enriched with ASN and risk flag
- **Domain WHOIS / registration** — registrar, registry domain ID, creation / updated / expiry dates, status codes, name servers, and (when not privacy-redacted) registrant org/address. Resolved from **authoritative registry RDAP** with a **port-43 WHOIS fallback** — queried directly from IANA → registry → registrar, with **no third-party WHOIS API**
- **Per-IP registry detail** — RIR, network name/range, allocation date and abuse contact, from RDAP
- **Real subdomain enumeration** via Certificate Transparency (crt.sh) — not a guess list
- **Geo-located hosts** on an accurate world map (Natural Earth projection), markers colored by role/risk
- **Edge / Origin classification** — whether the apex sits behind a CDN (masked) or resolves to a real host (exposed)
- **Origin candidates** from passive-DNS history (pre-CDN A records)
- **Authoritative ASN** per host via Team Cymru (reconciles RDAP/geo disagreements)
- **Bulletproof-ASN flagging** via Spamhaus ASN-DROP
- **Known-bad confirmation** via abuse.ch ThreatFox + URLhaus
- **Defanged IOCs** with copy buttons, plus export to **CSV**, **STIX 2.1**, and **MISP** event JSON
- **Bulk scanning** (paste a list, capped at 50, run concurrently)
- **Scan history** — every scan persisted locally, searchable, one-click recall
- **Active origin confirmation** (opt-in) — fetches a candidate with a spoofed `Host` header to verify it serves the target site; refuses private IPs and reports *inconclusive* rather than guessing
- **URLhaus submission** (gated) — contribute confirmed-malicious URLs back to the community

All sources are read-only/passive by default. The engine fails safe per source (a down
or keyless source degrades that section with a note; it never fabricates data).

## Prerequisites

The launchers need three things on your PATH: **Python 3** (with the `venv` module),
**Node.js**, and **npm**.

**Linux (Kali/Debian/Ubuntu)** — Python ships with the distro, but the `venv` module and
Node are separate packages:

```bash
sudo apt update
sudo apt install -y python3-venv nodejs npm
```

> On Kali, `python3 -m venv` requires the `python3-venv` package that matches your
> interpreter (e.g. `python3.13-venv`). If venv creation fails, `run.sh` tells you which
> package to install.

**macOS** — install both with [Homebrew](https://brew.sh):

```bash
brew install python node
```

**Windows** — install Python (tick *"Add python.exe to PATH"* in the installer) and
Node.js LTS (which bundles npm):

- Python: <https://www.python.org/downloads/>
- Node.js: <https://nodejs.org/>

Verify (Linux/macOS):

```bash
python3 --version && node -v && npm -v
```

Verify (Windows PowerShell):

```powershell
python --version; node -v; npm -v
```

## Get the code

**With git:**

```bash
git clone https://github.com/XecureLogic/origin-recon.git
cd origin-recon
```

**From an archive** (e.g. transferring to an offline box or a VM): copy the `.tar.gz`
over, then extract:

```bash
tar -xzf origin-recon-*.tar.gz
cd origin-recon
```

> **Moving the project between operating systems?** Copy **source only**. Never carry
> `node_modules/`, `backend/.venv/`, or `package-lock.json` from one OS to another — they
> contain compiled, platform-specific binaries that will fail on the other side. The
> launcher reinstalls them natively on first run. (`.gitattributes` keeps line endings
> correct across git checkouts automatically.)

## Quick start (one command)

**Linux / macOS:**

```bash
chmod +x run.sh     # first time only (the execute bit is not always preserved)
./run.sh            # build UI + serve on http://localhost:8000
./run.sh --dev      # hot-reload dev server (:5173) + backend (:8000)
```

**Windows (PowerShell):**

```powershell
.\run.ps1           # build UI + serve on http://localhost:8000
.\run.ps1 -Dev      # hot-reload dev server (:5173) + backend (:8000)
```

> First time on Windows you may need to allow the script to run in the current session:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

Then open http://localhost:8000

If a previous run was interrupted (a missing package, Ctrl+C mid-install), just run the
launcher again — it detects a half-built backend venv, rebuilds it, and refuses to
report success unless the backend is actually serving on port 8000.

Both launchers create a venv, install backend deps, build the frontend, serve the built
UI from the backend on port 8000, and open your browser. The `--dev` / `-Dev` flag runs
the hot-reload dev server instead. Ctrl+C stops everything.

## How to use

1. **Launch** with `./run.sh` (Linux/macOS) or `.\run.ps1` (Windows) and open
   **http://localhost:8000**. The header shows which enrichment sources are active
   (lit = key present).
2. **Scan a single domain** — type a domain (e.g. `example.com`) and press **Scan**.
   In a few seconds you get:
   - the **headline verdict** with plain-language reasoning,
   - the **Domain WHOIS** panel (registrar, dates, registry ID, name servers, status;
     registrant fields where the registry publishes them),
   - the **DNS graph**, the **geo map**, and the enriched **DNS records** table.
3. **Bulk scan** — switch to bulk mode and paste a list of domains (one per line, up to
   50). Results come back as a table; click **open** on any row for the full detail.
4. **Recall past scans** — every scan is saved locally. Open the **History** drawer
   (top-right), filter by domain, and click to reload — no re-scanning needed.
5. **Export** — from a scan, export **IOCs (CSV)**, **STIX 2.1**, or a **MISP** event
   for ingestion into a SIEM / TIP.
6. **Confirm an origin** (optional, active) — for a candidate origin IP, trigger the
   confirmation probe; it fetches the IP with the target's `Host` header and reports
   whether it serves the same site. This is the only feature that touches the target.
7. **Stop** — press **Ctrl+C** in the terminal running the launcher.

> Only scan domains you are authorized to assess.

## Optional API keys (enable richer enrichment)

Drop them in a `.env` at the project root (preferred) or in `backend/.env`. None are
hardcoded; each unlocks one module and the app degrades gracefully without it.

```bash
export IPINFO_TOKEN=...            # precise geolocation + ASN (raises rate limits)
export SECURITYTRAILS_API_KEY=...  # passive-DNS history (best for unmasking origins)
export VT_API_KEY=...              # passive-DNS history (VirusTotal)
export ABUSECH_AUTH_KEY=...        # known-bad confirmation (free: https://auth.abuse.ch/)
```

The header shows which enrichments are active. Without any keys you still get DNS, CT
subdomains, RDAP ASN, Team Cymru announced ASN, Spamhaus risk flagging, and approximate
(country-centroid) geolocation.

The status endpoint reports only **whether** a source is enabled — it never returns the
key. `.env` is git-ignored; keep it that way.

## Manual / dev mode

Backend (Linux/macOS):
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Backend (Windows PowerShell):
```powershell
cd backend
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Frontend (hot reload, separate terminal):
```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `env: 'bash\r': No such file or directory` (Linux) | `run.sh` has Windows (CRLF) line endings. Fix: `sed -i 's/\r$//' run.sh`. Cloning via git avoids this — `.gitattributes` forces LF. |
| `./run.sh: Permission denied` | Execute bit not set (common after extracting an archive). Fix: `chmod +x run.sh`. |
| `sh: 1: vite: Permission denied` / frontend build fails | `node_modules` was copied from another OS. Fix: `rm -rf frontend/node_modules frontend/package-lock.json` then rerun the launcher (it reinstalls natively). |
| Enrichment off even though you created a `.env` | The file must be named **exactly** `.env`. On Windows, Explorer/Notepad may save it as `.env.txt` (hidden extension). Rename it, and **restart** — `.env` is read only at launch. Check with `curl http://localhost:8000/api/config`. |
| `run.ps1` won't run (Windows) | Execution policy. Fix: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then `.\run.ps1`. |
| `python3 -m venv` fails (Debian/Kali) | Install the matching venv package: `sudo apt install python3-venv` (or e.g. `python3.13-venv`). |
| Port 8000 already in use | A previous backend is still running. Linux/macOS: `pkill -f 'uvicorn app.main'`. Windows: `Get-NetTCPConnection -LocalPort 8000 -State Listen \| Stop-Process -Id { $_.OwningProcess } -Force`. |
| Backend never becomes healthy | Read `backend.log` (or `backend.err.log` on Windows) — it shows the real startup error. |

## Notes

- Only scan domains you are authorized to assess.
- **WHOIS uses no third-party API** — it queries IANA → registry RDAP → registrar directly (port-43 fallback when a TLD has no RDAP). Registrant org/address are **usually redacted by the registry** under GDPR/ICANN policy for most gTLDs; the UI shows `Redacted` for privacy-masked fields and `—` for fields the registry never returned. Dates, registrar, registry ID, status and name servers are reliably present.
- IP enrichment and the WHOIS lookup run concurrently; a domain with many subdomains still completes in seconds.
- The world map is bundled offline (`frontend/src/assets/countries-110m.json`), so the app needs no external map service.
- The active origin-confirmation probe is the only feature that touches target infrastructure directly; it is opt-in per candidate.
