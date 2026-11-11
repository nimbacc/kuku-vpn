#!/usr/bin/env python3
"""
Kuku VPN v1.6.9 — Tor bridge snapshot builder (liveness-tested, random-sliced).

Sources (all optional; whatever CI managed to download):
    --moat-obfs4 FILE      official bridges.torproject.org web distribution
                           (FRESH obfs4 lines, shipped FIRST — newest
                           distribution = least likely blocked by ISP DPI)
    --moat-webtunnel FILE  same, webtunnel transport
    --stz-obfs4 FILE       scriptzteam/Tor-Bridges-Collector dump (STALE since
                           2026-07-29 — used only as volume filler)
    --stz-webtunnel FILE   same, webtunnel transport

Output (torrc "Bridge <line>" compatible):
    <out_dir>/tor_bridges_obfs4.txt
    <out_dir>/tor_bridges_webtunnel.txt

v1.6.9 — WHY the rewrite: the collector stopped updating on 2026-07-29 and on
the wire only ~11% of its July obfs4 lines still accepted a TCP connection
(verified from a clean vantage) — every APK since then shipped mostly corpses
and tor cycled dead endpoints into the boot cap (the user's regression). So:

  1. TCP LIVENESS TEST — every candidate is dial-tested from this runner
     (obfs4/webtunnel accept TCP before any handshake; an open port is what a
     dead bridge cannot fake). Only survivors ship.
  2. MOAT FIRST — the official distribution's lines are hours old, put at the
     head of the file; the app also puts fresh lines first in torrc.
  3. RANDOM SLICE of the alive pool (the v1.6.8 fix: a deterministic head of
     an IP-sorted dump always ships the same longest-exposed bridges).
  4. GARBAGE FILTER — private/reserved/loopback/known-anycast addresses can
     never host a bridge (the July dump contained e.g. "obfs4 1.0.0.1:9100").
  5. Zero alive bridges across ALL sources → exit 3 (CI then keeps the
     committed, itself liveness-tested snapshot).

The app repeats the same TCP test on-device before every tor boot
(TorEngine v1.6.9), so even a decayed snapshot no longer burns the boot cap.
"""
import argparse
import asyncio
import ipaddress
import os
import random
import re
import sys

OBF4_SAMPLE = 120  # alive collector lines shipped (moat lines extra, first)
WT_SAMPLE = 60

CONNECT_TIMEOUT_S = 6.0
CONCURRENCY = 160

FP_RE = re.compile(r"\b([0-9A-F]{40})\b")

# well-known anycast/reserved blocks that can never host a real bridge but
# appear in scraped dumps (the July 2026 collector dump had an obfs4 on 1.0.0.1)
FAKE_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "1.0.0.0/24", "1.1.1.0/24",
    "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "208.67.222.0/24",
    "2001:db8::/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)]


def clean_line(line):
    """The moat web page renders bridges as HTML text — strip tags/entities."""
    return re.sub(r"<[^>]+>", "", line).replace("&amp;", "&").strip()


def is_garbage_ip(ip_str: str) -> bool:
    try:
        o = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable address
    return (
        o.is_private or o.is_reserved or o.is_loopback or o.is_link_local
        or o.is_multicast or o.is_unspecified
        or any(o in net for net in FAKE_NETS)
    )


def parse_obfs4(raw_lines):
    """Dedupe by fingerprint; drop garbage addresses. Returns [(line, ip, port)]."""
    seen, out = set(), []
    for line in raw_lines:
        line = clean_line(line)
        if not line.startswith("obfs4 ") or " cert=" not in line:
            continue
        m = FP_RE.search(line)
        if not m:
            continue
        fp = m.group(1)
        if fp in seen:
            continue
        try:
            ip, port = line.split()[1].rsplit(":", 1)
            int(port)
        except (ValueError, IndexError):
            continue
        if is_garbage_ip(ip.strip("[]")):
            continue
        seen.add(fp)
        out.append((line, ip.strip("[]"), int(port)))
    return out


def parse_webtunnel(raw_lines):
    """Dedupe by url; keep doc-IPv6 placeholder addresses (the client dials
    the url= fronting domain by design). Returns [(line, host, port)]."""
    seen, out = set(), []
    for line in raw_lines:
        line = clean_line(line)
        if not line.startswith("webtunnel "):
            continue
        m = re.search(r"url=(\S+)", line)
        if not m:
            continue
        url = m.group(1)
        if url in seen:
            continue
        mm = re.match(r"https?://([^/:]+)(?::(\d+))?", url)
        if not mm:
            continue
        seen.add(url)
        out.append((line, mm.group(1), int(mm.group(2) or 443)))
    return out


async def probe(host, port):
    """TCP-connect probe — the bridge liveness oracle (TLS/obfs4 handshake
    happens after connect; an open port is what dead bridges cannot fake)."""
    try:
        fut = asyncio.open_connection(host, port)
        _, w = await asyncio.wait_for(fut, timeout=CONNECT_TIMEOUT_S)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def liveness(candidates, label):
    """TCP-test all candidates concurrently; return the alive subset (original order)."""
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(c):
        async with sem:
            ok = await probe(c[1], c[2])
        return (c, ok)

    results = await asyncio.gather(*(one(c) for c in candidates))
    alive = [c for (c, ok) in results if ok]
    print(f"  {label}: {len(candidates)} candidates -> {len(alive)} TCP-alive")
    return alive


def random_sample(items, n):
    """Randomly sample n lines — a NEW set on every build (the v1.6.8 fix:
    a deterministic head of an IP-sorted dump ships the same longest-exposed,
    already-swept bridges every time)."""
    if len(items) <= n:
        return list(items)
    idx = sorted(random.sample(range(len(items)), n))
    return [items[i] for i in idx]


def write_asset(path, header, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        f.write("\n".join(lines) + "\n")
    print(f"  wrote {len(lines)} lines -> {path}")


def read_lines(path):
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.readlines()


async def main_async(args):
    moat_ob = parse_obfs4(read_lines(args.moat_obfs4)) if args.moat_obfs4 else []
    moat_wt = parse_webtunnel(read_lines(args.moat_webtunnel)) if args.moat_webtunnel else []
    stz_ob = parse_obfs4(read_lines(args.stz_obfs4)) if args.stz_obfs4 else []
    stz_wt = parse_webtunnel(read_lines(args.stz_webtunnel)) if args.stz_webtunnel else []
    print(f"parsed: moat obfs4={len(moat_ob)} webtunnel={len(moat_wt)} | "
          f"collector obfs4={len(stz_ob)} webtunnel={len(stz_wt)}")

    moat_ob_alive = await liveness(moat_ob, "moat obfs4")
    moat_wt_alive = await liveness(moat_wt, "moat webtunnel")
    stz_ob_alive = await liveness(stz_ob, "collector obfs4")
    stz_wt_alive = await liveness(stz_wt, "collector webtunnel")

    ob_lines = [c[0] for c in moat_ob_alive] + \
        [c[0] for c in random_sample(stz_ob_alive, OBF4_SAMPLE)]
    wt_lines = [c[0] for c in moat_wt_alive] + \
        [c[0] for c in random_sample(stz_wt_alive, WT_SAMPLE)]

    os.makedirs(args.out_dir, exist_ok=True)
    write_asset(os.path.join(args.out_dir, "tor_bridges_obfs4.txt"),
                "# obfs4 bridges — moat (official) first, then TCP-alive collector slice (v1.6.9)",
                ob_lines)
    write_asset(os.path.join(args.out_dir, "tor_bridges_webtunnel.txt"),
                "# webtunnel bridges — moat (official) first, then TCP-alive collector slice (v1.6.9)",
                wt_lines)

    if not ob_lines and not wt_lines:
        print("ERROR: zero TCP-alive bridges — refusing to ship a dead snapshot",
              file=sys.stderr)
        sys.exit(3)
    if not ob_lines:
        print("WARNING: zero alive obfs4 bridges", file=sys.stderr)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("out_dir")
    p.add_argument("--moat-obfs4")
    p.add_argument("--moat-webtunnel")
    p.add_argument("--stz-obfs4")
    p.add_argument("--stz-webtunnel")
    a = p.parse_args()
    asyncio.run(main_async(a))
