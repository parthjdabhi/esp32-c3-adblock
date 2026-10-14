#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [--raw] [out.bin] [src ...]
  Output is a "C3BL" v1 file: 16-byte header (magic, version, hash size, count, CRC32)
  + the sorted hashes, so the device can reject a corrupt or random file. --raw writes
  just the hashes, for firmware older than the header change.
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + AdGuard DNS filter) ~= 230k entries: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
"""
import re
import sys, os, math, struct, urllib.request, zlib

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget):
# ads + trackers + malware, WhatsApp/social keep working. ~230k entries / 1.1 MB.
# AdGuard DNS filter covers far more ad/tracker domains than Hagezi Light (~98% vs ~71% of
# AdGuard's mobile-ads list, ~99% vs ~20% of EasyList's domain rules) and still fits.
# Hagezi Light alone (~57k) is the lighter option if flash is tight.
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',            # base: ads + malware
    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',          # AdGuard DNS filter (||domain^ rules)
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

# A real hostname: dot-separated labels of [a-z0-9_-]. Drops junk that some hosts files carry
# ("0.0.0.0", "-foo.gif", bare IPs) so it doesn't waste flash.
HOST = re.compile(r'^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$')
IPV4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def valid(d: str) -> bool:
    return bool(HOST.match(d)) and not IPV4.match(d)

def drop_covered(domains: set) -> set:
    """Remove subdomains whose parent is already listed. The firmware also checks every
    parent suffix (down to two labels), so a.ads.com is blocked anyway when ads.com is."""
    def covered(d):
        p = d.split('.')
        return any('.'.join(p[i:]) in domains for i in range(1, len(p) - 1))
    return {d for d in domains if not covered(d)}

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def container_header(count: int, payload: bytes) -> bytes:
    """C3BL v1 header -- must match checkBlocklist() in src/main.cpp."""
    return b'C3BL' + struct.pack('<BBHII', 1, HASH_BYTES, 0, count, zlib.crc32(payload) & 0xFFFFFFFF)

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    global ALLOW_MISSING
    args = [a for a in sys.argv[1:] if a not in ('--allow-missing', '--raw')]
    ALLOW_MISSING = '--allow-missing' in sys.argv[1:]
    raw = '--raw' in sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(('||', '@@')) else line.strip()
            if not line or line[0] in '!/[':
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    bad = {d for d in domains if not valid(d)}
    if bad:
        domains -= bad
        print(f'invalid names    : {len(bad):,} dropped (not a hostname)', file=sys.stderr)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    # after the allowlist, so a child of an allowed parent isn't dropped as "covered"
    before = len(domains); domains = drop_covered(domains)
    if before != len(domains):
        print(f'covered by parent: {before - len(domains):,} dropped (parent domain already blocked)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    payload = b''.join(h.to_bytes(HASH_BYTES, 'little') for h in uniq)
    with open(out, 'wb') as f:
        if not raw:
            f.write(container_header(len(uniq), payload))
        f.write(payload)

    n, size = len(uniq), os.path.getsize(out)
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
