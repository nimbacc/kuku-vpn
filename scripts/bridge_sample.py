#!/usr/bin/env python3
"""
Kuku VPN v1.6.0 — Tor bridge snapshot builder.

Takes the raw bridge dumps collected by scriptzteam/Tor-Bridges-Collector
(https://github.com/scriptzteam/Tor-Bridges-Collector) and produces the two
asset files the app bundles for the Tor "auto" bridge mode:

    app/src/main/assets/tor_bridges_obfs4.txt
    app/src/main/assets/tor_bridges_webtunnel.txt

Usage:
    bridge_sample.py <obfs4_raw> <webtunnel_raw> <out_dir>

Rules:
  - obfs4   : dedupe by fingerprint, evenly sample OBF4_SAMPLE lines.
  - webtunnel: dedupe by (addr,url), evenly sample WT_SAMPLE lines.
  - Output lines keep the original "obfs4 ..." / "webtunnel ..." format
    (torrc "Bridge <line>" compatible).
The CI refresh step runs this script after downloading fresh dumps; if the
download fails, the committed snapshots in app/src/main/assets stay as-is.
"""
import sys
import re

OBF4_SAMPLE = 150
WT_SAMPLE = 80


def even_sample(lines, n):
    """Evenly sample n lines preserving spread across the whole file."""
    if len(lines) <= n:
        return list(lines)
    step = len(lines) / float(n)
    return [lines[int(i * step)] for i in range(n)]


def sample_obfs4(raw_lines, n=OBF4_SAMPLE):
    seen, out = set(), []
    fp_re = re.compile(r"\b([0-9A-F]{40})\b")
    for line in raw_lines:
        line = line.strip()
        if not line.startswith("obfs4 ") or " cert=" not in line:
            continue
        m = fp_re.search(line)
        if not m:
            continue
        fp = m.group(1)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(line)
    return even_sample(out, n)


def sample_webtunnel(raw_lines, n=WT_SAMPLE):
    seen, out = set(), []
    for line in raw_lines:
        line = line.strip()
        if not line.startswith("webtunnel "):
            continue
        # NOTE: webtunnel bridge lines carry an RFC-3849 documentation IPv6
        # as a PLACEHOLDER address — the client dials the url= fronting
        # domain, not the address. Keep every line (the community's
        # distributor emits these dummies by design).
        addr = line.split()[1]
        url = ""
        m = re.search(r"url=(\S+)", line)
        if m:
            url = m.group(1)
        key = (addr, url)
        if key in seen:
            continue
        seen.add(key)
        out.append(line)
    return even_sample(out, n)


def main():
    obfs4_raw, wt_raw, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    import os
    os.makedirs(out_dir, exist_ok=True)

    with open(obfs4_raw, encoding="utf-8", errors="replace") as f:
        ob = sample_obfs4(f.readlines())
    with open(wt_raw, encoding="utf-8", errors="replace") as f:
        wt = sample_webtunnel(f.readlines())

    o_path = os.path.join(out_dir, "tor_bridges_obfs4.txt")
    w_path = os.path.join(out_dir, "tor_bridges_webtunnel.txt")
    with open(o_path, "w", encoding="utf-8") as f:
        f.write("# obfs4 bridges — scriptzteam collector snapshot\n")
        f.write("\n".join(ob) + "\n")
    with open(w_path, "w", encoding="utf-8") as f:
        f.write("# webtunnel bridges (IPv4) — scriptzteam collector snapshot\n")
        f.write("\n".join(wt) + "\n")
    print(f"obfs4: {len(ob)} lines -> {o_path}")
    print(f"webtunnel: {len(wt)} lines -> {w_path}")


if __name__ == "__main__":
    main()
