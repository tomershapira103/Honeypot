# Honeypot

A decoy SSH + RDP honeypot for GCP, built to answer questions about internet-wide scanning/brute-force traffic:

1. How long after the VM goes live until the first connection attempt, per port?
2. How many connection attempts land per port, per 24h?
3. What usernames and passwords do attackers try?
4. What SSH client tooling is behind the traffic (generic botnet vs. something more distinctive)?

Both services are **protocol-level decoys with no real backend** — an attacker can never get a real shell or a real remote desktop session, only a convincing-enough response to keep talking (and typing credentials) to the honeypot.

## How it works

```
Internet
  ├─ tcp:22   (0.0.0.0/0) ──▶ Cowrie container   (simulated SSH shell, always denies auth)
  ├─ tcp:3389 (0.0.0.0/0) ──▶ Trapster container (RDP protocol responder, always denies auth)
  └─ tcp:2200 (via GCP IAP only) ──▶ real sshd    (moved off port 22 so you keep admin access)
```

- **SSH (port 22)** is handled by [Cowrie](https://github.com/cowrie/cowrie), the standard medium-interaction SSH honeypot. It presents a simulated Linux shell (no real filesystem/process access) and is configured to **reject every credential** (`config/cowrie/etc/userdb.txt`), so brute-forcers keep trying instead of stopping after one "success."
- **RDP (port 3389)** is handled by [Trapster Community](https://github.com/0xBallpoint/trapster-community)'s RDP module only (every other protocol it supports is disabled). It completes just enough of the RDP/NLA handshake to capture a username and then always replies with `STATUS_LOGON_FAILURE` — there is no code path that ever grants a session.
- The real `sshd` is moved to **port 2200** by the VM's startup script, before the honeypot containers ever bind port 22, so you always have a way in. Port 2200 is never exposed to the public internet directly — it's only reachable through GCP's [Identity-Aware Proxy](https://cloud.google.com/iap/docs/using-tcp-forwarding) (IAP), which authenticates by your Google identity (IAM) rather than by source IP. That means admin access keeps working even if your home/office IP changes, with nothing to update.
- The VM is created with `--no-service-account --no-scopes`, so even a full compromise of the box can't reach any other GCP resource.

**Caveat:** RDP's NLA/CredSSP protocol never transmits the password in the clear. Trapster can only capture a plaintext **username** (from the pre-TLS connection cookie) plus a **NetNTLMv2 hash** (offline-crackable, e.g. hashcat mode 5600) — not a readable password. `analyze_logs.py` labels these rows accordingly and keeps them separate from SSH's genuinely-plaintext credentials.

## Repo layout

```
docker-compose.yml            # Cowrie (SSH) + Trapster (RDP-only) services
config/cowrie/etc/            # userdb.txt (deny-all), cowrie.cfg (overrides)
config/trapster/trapster.conf # RDP module only, append-mode JSON logging
deploy/
  config.sh.example           # copy to config.sh and fill in your GCP project id
  provision.sh                 # creates VPC, firewall rules, VM, deploys & starts the stack
  startup.sh                   # VM boot script: moves sshd to 2200, installs Docker
  teardown.sh                  # tears everything down when the study is over
analysis/
  analyze_logs.py              # parses both logs -> stats described below
data/                          # gitignored - captured logs land here after pulling them from the VM
```

## Deploying

```bash
cp deploy/config.sh.example deploy/config.sh
# edit deploy/config.sh: PROJECT_ID, REGION/ZONE

bash deploy/provision.sh
```

This creates an isolated VPC, three firewall rules (22 and 3389 open to the world, 2200 reachable only via GCP IAP), and an `e2-small` Debian 12 VM, then copies this repo onto it and starts the containers. Every resource-creation step is skipped if it already exists, so if the script fails partway through, just run it again.

Admin access afterward — open the IAP tunnel in one terminal, then SSH through it in another (`provision.sh` prints these two commands, with your values filled in, when it finishes):

```bash
gcloud compute start-iap-tunnel <instance> 2200 --local-host-port=localhost:12200 --project=<project> --zone=<zone>
ssh -i ~/.ssh/google_compute_engine -p 12200 <you>@localhost
```

This requires your Google account to have the `roles/iap.tunnelResourceAccessor` role or broader (project Owner/Editor already includes it) — no IP allowlisting to maintain. (We don't use `gcloud compute ssh --tunnel-through-iap` directly: on Windows it defaults to PuTTY's `plink.exe`, whose port flag is `-P` not `-p`, which breaks passing a custom port. The tunnel + plain `ssh` approach above works identically on Windows/Mac/Linux.)

## Verifying it's working

```bash
ssh <anything>@<external-ip>             # port 22 - any password, always rejected
xfreerdp /v:<external-ip> /u:test         # port 3389 - always rejected
```

Then check the logs on the VM (`data/cowrie/var/log/cowrie/cowrie.json`, `data/trapster/trapster.json`) for matching entries.

## Analyzing results

```bash
python analysis/analyze_logs.py \
  --cowrie-log data/cowrie/var/log/cowrie/cowrie.json \
  --trapster-log data/trapster/trapster.json \
  --deployment-marker analysis/deployment_marker.txt \
  --geoip
```

Prints, and writes as CSVs:

- **`attempts_per_24h.csv`** — time-to-first-attempt and connection counts bucketed into 24h windows, per port.
- **`credentials.csv`** — username/password combinations attackers tried, most common first.
- **`ssh_client_fingerprints.csv`** — the SSH client's raw identification banner (e.g. `SSH-2.0-libssh_0.9.6`) and its [HASSH](https://github.com/salesforce/hassh) key-exchange fingerprint, both taken from events Cowrie already logs - useful for spotting whether traffic is dominated by a handful of generic scanning tools/botnets or something more varied.
- **`source_ips.csv`** — connection counts per source IP, per port. Pass `--geoip` to also enrich each unique IP with country/ISP via the free [ip-api.com](https://ip-api.com) API (rate-limited to ~1 request/1.5s, so this is the one part of the script that touches the network - omit the flag to stay fully offline).

## Tearing down

```bash
bash deploy/teardown.sh
```

Pulls a reminder to grab the logs first, then deletes the VM, firewall rules, subnet, and VPC in order. Expect roughly $14-18/month while the VM is running (`e2-small` + a small disk + negligible egress).

## Safety notes

- Never commit `deploy/config.sh` or anything under `data/` (both are gitignored) - they contain your GCP project id and captured attacker data respectively.
- Neither honeypot rotates its JSON log by default; fine for a study running days to a few weeks, but download and truncate the logs periodically for longer runs.

## Possible follow-on research

Not implemented here, but natural extensions if you want to go further:

- **ASN-level correlation across IPs** (e.g. grouping many source IPs by hosting provider to spot shared scanning infrastructure) — `source_ips.csv` has per-IP ISP/org data from `--geoip`, but nothing aggregates across rows yet.
- **Correlating IPs with threat-intel feeds** (e.g. AbuseIPDB) — Cowrie has a built-in output plugin for this, just needs an API key.
- **Post-login attacker behavior** (commands run, malware downloaded) — requires letting some login attempts succeed, which trades off against this project's "always deny" choice of maximizing distinct credentials captured. Best run as a separate instance/config rather than changing the primary one.
