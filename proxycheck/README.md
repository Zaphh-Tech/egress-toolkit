# proxycheck

Egress inventory for authorized security testing. `pip install 'requests[socks]'`
(already present on this box: requests 2.32.5, PySocks 1.7.1).

## inventory — health of your proxies, touches no target

    python3 proxycheck.py inventory -f proxies.txt

    LABEL                  EGRESS IP        GEO    ASN           LAT  STATUS
    residential-eu         203.0.113.9      DE     AS3320      412ms  up
    dc-lon                 198.51.100.4     GB     AS16509     88ms   up  [datacenter IP]

Proxy list format, one per line:

    socks5h://user:pass@host:1080   # residential-eu
    https://user:pass@host:8443     # corp-jump

Reports egress IP, country, ASN, latency, and three things that actually bite:

- **DNS leaks.** `socks5://` resolves hostnames on *your* machine, so your
  resolver logs every target you visit even though the traffic is proxied.
  `socks5h://` hands the hostname to the proxy. The tool flags every entry using
  the leaky form and tells you the fix.
- **Datacenter IPs**, which are trivially identifiable as such.
- **IPs already publicly catalogued as proxies**, per ip-api's classification.

`--no-geo` skips the third-party lookup. `--json out.json` also dumps structured
results. Concurrency defaults to 4 — deliberately low.

## diagnose — one proxy, one target, one request

    python3 proxycheck.py diagnose --url https://target.example/api --proxy socks5h://...
    python3 proxycheck.py diagnose --url https://target.example/api      # direct

Sends a single request, identifies the edge (CloudFront, Cloudflare, Akamai,
Imperva, AWS WAF, Fastly), and if you're blocked, drafts the allowlist request
with the evidence already filled in — source IP, status, reference ID, timestamp.

Verified working: correctly identified Cloudflare on a live 200 and reported the
CF-RAY.

## What this deliberately does not do

No User-Agent rotation to find one that passes, no sweeping a proxy list against
a target hunting for an unblocked IP, no "burned proxy" tracking. That is an
evasion loop, and evading a target's anti-abuse layer is outside what a bug
bounty scope authorizes — which is why every mature program has an allowlist
process instead. `diagnose` is one proxy against one target precisely so it
stays a diagnostic rather than a search.

Ask for the allowlist. Once they give you a marker header, put it on the profile
in `hunt-containers` so it rides every request automatically.
