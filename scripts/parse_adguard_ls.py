#!/usr/bin/env python3
"""Convert an AdGuard/ABP DNS list to bare-domain list for Loyalsoldier/v2ray-rules-dat style data files.

Usage: python3 parse_adguard_ls.py <source> <output> [report]
Output: one bare domain per line (bare = subdomain match in v2fly geosite format).
"""
from pathlib import Path
from collections import Counter
import re, sys

SOURCE = Path(sys.argv[1] if len(sys.argv) > 1 else "dns.txt")
OUTPUT = Path(sys.argv[2] if len(sys.argv) > 2 else "custom-ads.txt")
REPORT = Path(sys.argv[3] if len(sys.argv) > 3 else "conversion-report.txt")

plain = re.compile(r"^\|\|([A-Za-z0-9.-]+)\^$")
valid = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
counts = Counter()
domains = set()
excluded = []

if not SOURCE.is_file() or SOURCE.stat().st_size == 0:
    sys.exit(f"Missing or empty source: {SOURCE}")

for raw in SOURCE.read_text(encoding="utf-8-sig", errors="replace").splitlines():
    s = raw.strip()
    if not s:
        counts["blank"] += 1
    elif s.startswith(("!", "#")) or s == "[Adblock Plus 2.0]":
        counts["comment/header"] += 1
    elif s.startswith("@@"):
        counts["exception"] += 1
        excluded.append(s)
    elif s.startswith("/") and s.endswith("/"):
        counts["regex"] += 1
        excluded.append(s)
    elif s.startswith("||") and "*" in s:
        counts["wildcard"] += 1
        excluded.append(s)
    else:
        m = plain.fullmatch(s)
        if not m:
            counts["other"] += 1
            excluded.append(s)
            continue
        d = m.group(1).lower().rstrip(".")
        if valid.fullmatch(d):
            counts["plain-domain"] += 1
            domains.add(d)
        else:
            counts["invalid-domain"] += 1
            excluded.append(s)

if not domains:
    sys.exit("No valid domains extracted; refusing to write an empty ruleset.")

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
lines = [d for d in sorted(domains)]
OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

REPORT.parent.mkdir(parents=True, exist_ok=True)
rep = [f"Source lines: {sum(counts.values())}",
       f"Unique domains: {len(domains)}"]
rep.extend(f"{k}: {v}" for k, v in sorted(counts.items()))
rep.append("Excluded examples (up to 200):")
rep.extend(excluded[:200])
REPORT.write_text("\n".join(rep) + "\n", encoding="utf-8")

print(f"Converted {len(domains)} unique domains -> {OUTPUT}")
print(f"Report -> {REPORT}")
