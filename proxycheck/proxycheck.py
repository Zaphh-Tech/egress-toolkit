#!/usr/bin/env python3
"""
proxycheck - egress inventory for authorized security testing.

Two modes, deliberately separate:

  inventory   Health of YOUR proxies: is it up, what IP does it egress from,
              where is that IP, how slow is it, does it leak DNS. Touches no
              target.

  diagnose    ONE proxy, ONE target, ONE request. Tells you whether you are
              being blocked and by what, and drafts the allowlist request to
              send the program.

What it will not do: rotate User-Agents to find one that passes, sweep a proxy
list against a target looking for an unblocked IP, or track "burned" IPs to
rotate away from. If a WAF is blocking your authorized testing, the fix is an
allowlist from the program, not a better disguise. `diagnose` exists to get you
the evidence for that request.
"""

import argparse
import concurrent.futures as cf
import json
import re
import sys
import time
import urllib.parse

try:
    import requests
except ImportError:
    sys.exit("needs: pip install 'requests[socks]'")

try:
    import socks  # noqa: F401  (PySocks - required for socks5 support)
except ImportError:
    sys.exit("needs: pip install 'requests[socks]'  (PySocks missing)")


IP_ECHO = "https://api.ipify.org?format=json"
GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,org,proxy,hosting"

# One honest, declared UA. Not rotated. Override with --ua if your program
# requires a specific marker string.
DEFAULT_UA = "proxycheck/1.0 (authorized security testing)"


# ----------------------------------------------------------------- proxies
class Proxy:
    def __init__(self, url, label=None):
        self.raw = url
        parts = urllib.parse.urlsplit(url)
        if not parts.scheme or not parts.hostname:
            raise ValueError(f"cannot parse proxy: {url!r}")
        self.scheme = parts.scheme.lower()
        self.host = parts.hostname
        self.port = parts.port
        self.label = label or f"{self.host}:{self.port}"

    @property
    def leaks_dns(self):
        """socks5:// resolves hostnames locally -> your resolver sees every
        target you visit even though the traffic is proxied. socks5h:// hands
        the hostname to the proxy. Same for socks4 vs socks4a."""
        return self.scheme in ("socks5", "socks4")

    @property
    def fixed(self):
        return {"socks5": "socks5h", "socks4": "socks4a"}.get(self.scheme, self.scheme)

    def as_dict(self):
        return {"http": self.raw, "https": self.raw}

    def __repr__(self):
        return f"<Proxy {self.label} {self.scheme}>"


def load_proxies(path):
    """One per line.  socks5h://user:pass@host:1080  #optional-label
    Blank lines and lines starting with # are skipped."""
    out = []
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            label = None
            if "#" in line:
                line, label = (x.strip() for x in line.split("#", 1))
            try:
                out.append(Proxy(line, label))
            except ValueError as e:
                print(f"  line {n}: {e}", file=sys.stderr)
    return out


# ----------------------------------------------------------------- probes
def egress(proxy, timeout, ua):
    """Ask an IP echo service what address we come from. Never touches a target."""
    t0 = time.time()
    try:
        r = requests.get(
            IP_ECHO,
            proxies=proxy.as_dict() if proxy else None,
            timeout=timeout,
            headers={"User-Agent": ua},
        )
        ms = int((time.time() - t0) * 1000)
        if r.status_code != 200:
            return {"ok": False, "err": f"HTTP {r.status_code}", "ms": ms}
        return {"ok": True, "ip": r.json().get("ip"), "ms": ms}
    except requests.exceptions.ProxyError as e:
        return {"ok": False, "err": "proxy refused", "ms": int((time.time() - t0) * 1000),
                "detail": str(e)[:120]}
    except requests.exceptions.ConnectTimeout:
        return {"ok": False, "err": "connect timeout", "ms": int((time.time() - t0) * 1000)}
    except requests.exceptions.ReadTimeout:
        return {"ok": False, "err": "read timeout", "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "err": type(e).__name__, "ms": int((time.time() - t0) * 1000),
                "detail": str(e)[:120]}


def geo(ip, timeout=6):
    try:
        r = requests.get(GEO_API.format(ip=ip), timeout=timeout)
        d = r.json()
        if d.get("status") != "success":
            return {}
        return {
            "cc": d.get("countryCode", "??"),
            "country": d.get("country", ""),
            "asn": (d.get("as") or "").split()[0] if d.get("as") else "",
            "org": d.get("org", ""),
            "flagged_proxy": bool(d.get("proxy")),
            "hosting": bool(d.get("hosting")),
        }
    except Exception:
        return {}


# ----------------------------------------------------------------- inventory
def cmd_inventory(args):
    proxies = load_proxies(args.file)
    if not proxies:
        sys.exit("no usable proxies in that file")

    print(f"Checking {len(proxies)} proxies (concurrency {args.concurrency})…\n")

    rows = []
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(egress, p, args.timeout, args.ua): p for p in proxies}
        for fut in cf.as_completed(futs):
            p = futs[fut]
            res = fut.result()
            g = geo(res["ip"]) if (res["ok"] and not args.no_geo) else {}
            rows.append((p, res, g))

    rows.sort(key=lambda r: (not r[1]["ok"], r[1]["ms"]))

    hdr = f"{'LABEL':<22} {'EGRESS IP':<16} {'GEO':<6} {'ASN':<9} {'LAT':>7}  STATUS"
    print(hdr)
    print("-" * len(hdr))
    for p, res, g in rows:
        if res["ok"]:
            status = "up"
            if g.get("hosting"):
                status += "  [datacenter IP]"
            if g.get("flagged_proxy"):
                status += "  [publicly flagged as proxy]"
            print(f"{p.label[:22]:<22} {res['ip']:<16} {g.get('cc','??'):<6} "
                  f"{g.get('asn','')[:9]:<9} {res['ms']:>5}ms  {status}")
        else:
            print(f"{p.label[:22]:<22} {'-':<16} {'-':<6} {'-':<9} {res['ms']:>5}ms  "
                  f"DOWN: {res['err']}")

    # correctness warnings that actually matter
    leaky = [p for p in proxies if p.leaks_dns]
    if leaky:
        print("\nDNS leak warning")
        print("  These are configured to resolve hostnames locally, so your resolver "
              "sees\n  every target you visit even though the traffic is proxied:")
        for p in leaky:
            print(f"    {p.label:<22} {p.scheme}://…  ->  use {p.fixed}://… instead")

    dc = [p.label for p, _, g in rows if g.get("hosting")]
    if dc:
        print("\nNote: datacenter IPs are trivially identifiable as such. If a program "
              "asked\n  you to test from a specific egress, confirm these match what you "
              "declared:\n    " + ", ".join(dc))

    if args.json:
        out = [{"label": p.label, "scheme": p.scheme, **res, **g} for p, res, g in rows]
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwrote {args.json}")


# ----------------------------------------------------------------- diagnose
BLOCK_VENDORS = [
    ("CloudFront", lambda h, b: "cloudfront" in h.get("via", "").lower()
                                or "cloudfront" in h.get("x-cache", "").lower()
                                or "x-amz-cf-id" in h),
    ("AWS WAF",    lambda h, b: "awselb" in h.get("server", "").lower()
                                or "aws-waf" in b.lower()),
    ("Cloudflare", lambda h, b: "cloudflare" in h.get("server", "").lower()
                                or "cf-ray" in h),
    ("Akamai",     lambda h, b: "akamai" in h.get("server", "").lower()
                                or "akamaighost" in h.get("server", "").lower()
                                or "x-akamai-request-id" in h),
    ("Imperva",    lambda h, b: "incap_ses" in str(h.get("set-cookie", ""))
                                or "x-iinfo" in h),
    ("Fastly",     lambda h, b: "fastly" in h.get("via", "").lower()
                                or "x-served-by" in h),
]


def identify_vendor(headers, body):
    h = {k.lower(): v for k, v in headers.items()}
    hits = [name for name, test in BLOCK_VENDORS if test(h, body)]
    return hits


def cmd_diagnose(args):
    """One proxy, one target, one request. A diagnostic, not a search."""
    proxy = Proxy(args.proxy) if args.proxy else None
    url = args.url

    print(f"target : {url}")
    print(f"egress : {proxy.label if proxy else 'direct (no proxy)'}")

    e = egress(proxy, args.timeout, args.ua)
    if not e["ok"]:
        sys.exit(f"\nproxy is not usable: {e['err']}\n{e.get('detail','')}")
    g = geo(e["ip"]) if not args.no_geo else {}
    print(f"     -> {e['ip']}  {g.get('country','')} {('('+g['asn']+')') if g.get('asn') else ''}"
          f"  {e['ms']}ms\n")

    t0 = time.time()
    try:
        r = requests.get(
            url,
            proxies=proxy.as_dict() if proxy else None,
            timeout=args.timeout,
            headers={"User-Agent": args.ua, "Accept": "*/*"},
            allow_redirects=False,
        )
    except Exception as ex:
        sys.exit(f"request failed: {type(ex).__name__}: {ex}")
    ms = int((time.time() - t0) * 1000)
    body = r.text[:4000]

    print(f"HTTP {r.status_code}   {ms}ms   {len(r.content)} bytes")
    interesting = ["server", "via", "x-cache", "x-amz-cf-id", "cf-ray",
                   "x-akamai-request-id", "retry-after", "x-iinfo", "x-served-by"]
    for k in interesting:
        for hk, hv in r.headers.items():
            if hk.lower() == k:
                print(f"  {hk}: {hv}")

    vendors = identify_vendor(r.headers, body)
    if vendors:
        print(f"\nedge  : {', '.join(vendors)}")

    blocked = r.status_code in (403, 405, 406, 429, 503)
    if not blocked:
        print("\nNot blocked from this egress. Nothing to escalate.")
        return

    ref = None
    m = re.search(r"[Rr]equest\s*ID[:\s]+([A-Za-z0-9_\-=]+)", body)
    if m:
        ref = m.group(1)
    for hk in ("x-amz-cf-id", "cf-ray", "x-akamai-request-id"):
        if hk in {k.lower() for k in r.headers}:
            ref = ref or r.headers.get(hk) or r.headers.get(hk.upper())

    print(f"\nBlocked at the edge ({r.status_code}).")
    print("This is anti-abuse infrastructure, not the application. Working around it")
    print("is out of scope on most programs and is what the allowlist process exists")
    print("for. Draft below — send it through the program's channel.\n")

    print("-" * 68)
    print(f"""Subject: Request for testing allowlist — egress {e['ip']}

Hi,

I'm testing under your bug bounty program and my requests are being blocked at
the edge before they reach the application, so I can't assess the in-scope
surface.

  Target        : {url}
  Source IP     : {e['ip']}{(chr(10) + '  Location      : ' + g.get('country','')) if g.get('country') else ''}
  Response      : HTTP {r.status_code}{(chr(10) + '  Edge          : ' + ', '.join(vendors)) if vendors else ''}{(chr(10) + '  Reference ID  : ' + str(ref)) if ref else ''}
  Observed at   : {time.strftime('%Y-%m-%d %H:%M:%S %Z')}
  User-Agent    : {args.ua}

Could you allowlist this source IP for the duration of my testing, or tell me
the marker header you'd like me to send so your WAF can identify my traffic?

I'll keep all testing to the documented scope and rate limits.

Thanks,
""")
    print("-" * 68)
    print("\nAdd your handle and the program name before sending.")
    print("Once they give you a marker header, put it on the profile in "
          "hunt-containers\nso it rides every request automatically.")


# ----------------------------------------------------------------- cli
def main():
    # shared flags, accepted before OR after the subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--timeout", type=float, default=12)
    common.add_argument("--ua", default=DEFAULT_UA,
                        help="declared User-Agent (not rotated)")
    common.add_argument("--no-geo", action="store_true",
                        help="skip the geolocation lookup")

    ap = argparse.ArgumentParser(
        prog="proxycheck", description=__doc__, parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    inv = sub.add_parser("inventory", parents=[common],
                         help="health of your proxies; touches no target")
    inv.add_argument("-f", "--file", required=True, help="proxy list file")
    inv.add_argument("-c", "--concurrency", type=int, default=4)
    inv.add_argument("--json", help="also write results to this JSON file")
    inv.set_defaults(func=cmd_inventory)

    dia = sub.add_parser("diagnose", parents=[common],
                         help="one proxy, one target, one request")
    dia.add_argument("--url", required=True, help="in-scope target URL")
    dia.add_argument("--proxy", help="proxy URL; omit to test your direct connection")
    dia.set_defaults(func=cmd_diagnose)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
