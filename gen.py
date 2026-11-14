#!/usr/bin/env python3
"""Build RouterOS address-list .rsc files from APNIC delegated data (country=CN only).

HK / MO / TW have their own country codes (HK/MO/TW) in the APNIC file, so they are excluded.
Fails (non-zero exit) if the result looks wrong, so a bad run never overwrites good output.
"""
import ipaddress
import sys
import urllib.request
from pathlib import Path

URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
OUT = Path(__file__).parent / "dist"
LIST_NAME = "cn_ip_cidr"         # imported directly into the live list
MIN_V4, MIN_V6 = 3000, 300       # sanity floor (after merging)
VALID_STATUS = {"allocated", "assigned"}


def fetch(src: str) -> str:
    if src.startswith("http"):
        req = urllib.request.Request(src, headers={"User-Agent": "cnip-gen"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode("utf-8")
    return Path(src).read_text()


def parse(text: str):
    v4, v6 = [], []
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        p = line.split("|")
        if len(p) < 7 or p[0] != "apnic" or p[1] != "CN" or p[6] not in VALID_STATUS:
            continue
        if p[2] == "ipv4":
            start = ipaddress.IPv4Address(p[3])
            end = ipaddress.IPv4Address(int(start) + int(p[4]) - 1)
            v4.extend(ipaddress.summarize_address_range(start, end))  # count may not be a power of 2
        elif p[2] == "ipv6":
            v6.append(ipaddress.IPv6Network(f"{p[3]}/{p[4]}"))
    return list(ipaddress.collapse_addresses(v4)), list(ipaddress.collapse_addresses(v6))


def write_rsc(path: Path, nets, cmd: str):
    with path.open("w") as f:
        f.write(f"{cmd}\n")
        for n in nets:
            f.write(f"add list={LIST_NAME} address={n}\n")


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else URL
    v4, v6 = parse(fetch(src))
    if len(v4) < MIN_V4 or len(v6) < MIN_V6:
        sys.exit(f"sanity check failed: v4={len(v4)} v6={len(v6)}")
    OUT.mkdir(exist_ok=True)
    write_rsc(OUT / "cn_ip4.rsc", v4, "/ip firewall address-list")
    write_rsc(OUT / "cn_ip6.rsc", v6, "/ipv6 firewall address-list")
    (OUT / "cn_ip4.txt").write_text("\n".join(map(str, v4)) + "\n")
    (OUT / "cn_ip6.txt").write_text("\n".join(map(str, v6)) + "\n")
    print(f"ok: v4={len(v4)} v6={len(v6)}")


if __name__ == "__main__":
    main()
