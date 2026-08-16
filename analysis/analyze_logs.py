"""
Parses Cowrie (SSH) and Trapster (RDP) JSON-lines logs and reports:
  1. Time from deployment to the first connection attempt, per port.
  2. Connection attempts bucketed into 24h windows, per port.
  3. Frequency of username/password combinations attackers tried.
  4. Frequency of SSH client fingerprints (banner string and HASSH), which
     hints at whether traffic is generic botnet tooling or something more
     targeted. Both come from events Cowrie already emits, so this needs no
     external API or GeoIP-style database.

Usage:
    python analyze_logs.py \
        --cowrie-log data/cowrie/var/log/cowrie/cowrie.json \
        --trapster-log data/trapster/trapster.json \
        --deployment-marker analysis/deployment_marker.txt \
        --out-dir analysis

Note: RDP passwords are NOT plaintext (RDP's NLA/CredSSP protocol never
sends the password unencrypted). The "password" column for RDP rows is
either empty (username-only, from the pre-auth connection cookie) or a
NetNTLMv2 hash (crackable offline, e.g. with hashcat mode 5600) - it is
labeled accordingly and kept separate from SSH's genuinely-plaintext
credentials.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class Attempt:
    port_label: str  # "22/ssh" or "3389/rdp"
    event: str  # "connect" or "login"
    timestamp: datetime
    src_ip: str
    username: str | None
    password: str | None
    password_kind: str | None  # None, "plaintext", or "ntlmv2_hash"


@dataclass
class Fingerprint:
    kind: str  # "ssh_client_version" or "ssh_hassh"
    value: str
    timestamp: datetime
    src_ip: str


def parse_cowrie(path: Path) -> tuple[list[Attempt], list[Fingerprint]]:
    """Read cowrie.json, returning (attempts, client fingerprints)."""
    attempts: list[Attempt] = []
    fingerprints: list[Fingerprint] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        # datetime.fromisoformat() only accepts a trailing "Z" from Python 3.11
        # onwards; normalize it ourselves for compatibility with 3.10 and earlier.
        ts = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
        event_id = record["eventid"]
        if event_id == "cowrie.session.connect":
            attempts.append(Attempt("22/ssh", "connect", ts, record["src_ip"], None, None, None))
        elif event_id == "cowrie.login.failed":
            attempts.append(
                Attempt(
                    "22/ssh",
                    "login",
                    ts,
                    record["src_ip"],
                    record.get("username"),
                    record.get("password"),
                    "plaintext",
                )
            )
        elif event_id == "cowrie.client.version":
            # The client's raw SSH identification banner (e.g. "SSH-2.0-libssh_0.9.6").
            # Real interactive clients and mass-scanning bots tend to use very
            # different, recognizable banners.
            fingerprints.append(Fingerprint("ssh_client_version", record["version"], ts, record["src_ip"]))
        elif event_id == "cowrie.client.kex":
            # HASSH: a fingerprint derived from the client's key-exchange proposal.
            # More robust than the banner alone, since some tools spoof a generic
            # banner but still negotiate a distinctive set of algorithms.
            fingerprints.append(Fingerprint("ssh_hassh", record["hassh"], ts, record["src_ip"]))
    return attempts, fingerprints


def parse_trapster(path: Path) -> list[Attempt]:
    """Read trapster.json, yielding one Attempt per rdp.connection / rdp.login."""
    attempts: list[Attempt] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        ts = datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S.%f").replace(
            tzinfo=timezone.utc
        )
        log_type = record["logtype"]
        if log_type == "rdp.connection":
            attempts.append(Attempt("3389/rdp", "connect", ts, record["src_ip"], None, None, None))
        elif log_type == "rdp.login":
            extra = record.get("extra", {})
            username = extra.get("username") or None
            password = extra.get("password") or None
            # The NLA stage reports a "domain\username" NetNTLMv2 hash, not a
            # readable password - the pre-TLS cookie stage has no password at all.
            kind = "ntlmv2_hash" if password else None
            attempts.append(Attempt("3389/rdp", "login", ts, record["src_ip"], username, password, kind))
    return attempts


def load_deployment_time(path: Path) -> datetime:
    text = path.read_text(encoding="utf-8").strip()
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def time_to_first_attempt(attempts: list[Attempt], deployed_at: datetime) -> dict[str, timedelta]:
    """Elapsed time from deployment to the first 'connect' event, per port."""
    first_seen: dict[str, datetime] = {}
    for attempt in attempts:
        if attempt.event != "connect":
            continue
        current = first_seen.get(attempt.port_label)
        if current is None or attempt.timestamp < current:
            first_seen[attempt.port_label] = attempt.timestamp
    return {port: ts - deployed_at for port, ts in first_seen.items()}


def counts_per_24h(attempts: list[Attempt], deployed_at: datetime) -> Counter[tuple[str, int]]:
    """Count 'connect' events per port, bucketed into 24h windows since deployment."""
    counts: Counter[tuple[str, int]] = Counter()
    for attempt in attempts:
        if attempt.event != "connect":
            continue
        day_index = (attempt.timestamp - deployed_at) // timedelta(hours=24)
        counts[(attempt.port_label, day_index)] += 1
    return counts


def credential_frequency(attempts: list[Attempt]) -> Counter[tuple[str, str, str, str]]:
    """Count (port, username, password, password_kind) over 'login' events with a username."""
    counter: Counter[tuple[str, str, str, str]] = Counter()
    for attempt in attempts:
        if attempt.event != "login" or not attempt.username:
            continue
        key = (
            attempt.port_label,
            attempt.username,
            attempt.password or "",
            attempt.password_kind or "none",
        )
        counter[key] += 1
    return counter


def fingerprint_frequency(fingerprints: list[Fingerprint]) -> Counter[tuple[str, str]]:
    """Count (kind, value) occurrences over all client fingerprint events."""
    counter: Counter[tuple[str, str]] = Counter()
    for fp in fingerprints:
        counter[(fp.kind, fp.value)] += 1
    return counter


def write_csv(path: Path, header: list[str], rows: list[tuple]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def print_summary(
    time_to_first: dict[str, timedelta],
    counts: Counter[tuple[str, int]],
    credentials: Counter[tuple[str, str, str, str]],
    fingerprints: Counter[tuple[str, str]],
) -> None:
    print("=== Time to first connection attempt ===")
    for port, delta in sorted(time_to_first.items()):
        print(f"  {port}: {delta}")

    print("\n=== Connection attempts per 24h window ===")
    for (port, day_index), count in sorted(counts.items()):
        print(f"  {port} day {day_index}: {count} attempts")

    print("\n=== Top 20 credential combinations ===")
    for (port, username, password, kind), count in credentials.most_common(20):
        shown_password = password if kind != "ntlmv2_hash" else f"{password[:40]}... (ntlmv2_hash)"
        print(f"  {port} {username!r}/{shown_password!r} [{kind}]: {count}x")

    print("\n=== Top 20 SSH client fingerprints ===")
    for (kind, value), count in fingerprints.most_common(20):
        print(f"  [{kind}] {value}: {count}x")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cowrie-log", type=Path, default=Path("data/cowrie/var/log/cowrie/cowrie.json"))
    parser.add_argument("--trapster-log", type=Path, default=Path("data/trapster/trapster.json"))
    parser.add_argument("--deployment-marker", type=Path, default=Path("analysis/deployment_marker.txt"))
    parser.add_argument("--out-dir", type=Path, default=Path("analysis"))
    args = parser.parse_args()

    deployed_at = load_deployment_time(args.deployment_marker)
    attempts: list[Attempt] = []
    fingerprints: list[Fingerprint] = []
    if args.cowrie_log.exists():
        cowrie_attempts, fingerprints = parse_cowrie(args.cowrie_log)
        attempts += cowrie_attempts
    if args.trapster_log.exists():
        attempts += parse_trapster(args.trapster_log)

    if not attempts:
        print("No log data found yet.")
        return

    time_to_first = time_to_first_attempt(attempts, deployed_at)
    counts = counts_per_24h(attempts, deployed_at)
    credentials = credential_frequency(attempts)
    fingerprint_counts = fingerprint_frequency(fingerprints)

    print_summary(time_to_first, counts, credentials, fingerprint_counts)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        args.out_dir / "attempts_per_24h.csv",
        ["port", "day_index", "attempts"],
        [(port, day, count) for (port, day), count in sorted(counts.items())],
    )
    write_csv(
        args.out_dir / "credentials.csv",
        ["port", "username", "password", "password_kind", "count"],
        [
            (port, username, password, kind, count)
            for (port, username, password, kind), count in credentials.most_common()
        ],
    )
    write_csv(
        args.out_dir / "ssh_client_fingerprints.csv",
        ["kind", "value", "count"],
        [(kind, value, count) for (kind, value), count in fingerprint_counts.most_common()],
    )
    print(f"\nCSV reports written to {args.out_dir}/")


if __name__ == "__main__":
    main()
