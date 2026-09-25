# egress-toolkit

Per-identity egress routing and proxy-fleet diagnostics for **authorized** security
testing.

Two independent components that solve one problem: running several isolated test
identities from a single machine, over proxies you control, without leaking your
real IP or your target hostnames — and knowing the health of those proxies before
you rely on them.

| Component | What it is | Language |
|-----------|-----------|----------|
| [`hunt-containers/`](hunt-containers/) | Firefox extension: binds each tab/container to its own upstream proxy, with isolated cookie jars and mandatory marker headers | JavaScript (MV3) |
| [`proxycheck/`](proxycheck/) | CLI: proxy-fleet health inventory + single-request edge diagnostics | Python (stdlib + `requests[socks]`) |

---

## The problem

Authorization testing — IDOR/BOLA, tenant isolation, cross-account state — needs
**two accounts live at the same time, in sessions that cannot see each other.** Do
that naively and three things go wrong:

1. Cookies bleed between accounts, so "account A reading account B's object"
   isn't actually proven.
2. A dead or misconfigured proxy silently falls back to your **real IP**.
3. A `socks5://` proxy resolves target hostnames on **your** machine, so your
   resolver logs every target even though the traffic is proxied.

`egress-toolkit` closes all three.

## Architecture

```
                          ┌─────────────────────── Firefox ───────────────────────┐
                          │                                                        │
   Tab (container acct-a) │──▶ hunt-containers ──▶ proxy profile P1 ──┐            │
   Tab (container acct-b) │──▶   proxy.onRequest ▶ proxy profile P2 ──┤            │
   Tab (unbound)          │──▶   (no binding) ────────────── DIRECT ──┤            │
                          │           │                                │           │
                          │           ├─ isolated cookie jar per container         │
                          │           ├─ static marker header per profile          │
                          │           └─ proxyDNS on  (proxy resolves hostnames)    │
                          └────────────────────────────────────────────┼──────────┘
                                                                        │
                                          SOCKS5 / HTTPS upstream proxies (yours)
                                                                        │
                                                                        ▼
                                                              in-scope target(s)

   proxycheck  ──inventory──▶  IP echo + geo/ASN  ──▶  health table + DNS-leak /
      (offline, no      │        (touches no target)      datacenter / flagged-proxy
       target contact)  │                                  warnings
                        └──diagnose──▶ one proxy → one target → one request
                                       └─ fingerprint edge (CloudFront / Cloudflare /
                                          Akamai / Imperva / AWS WAF / Fastly)
                                       └─ if blocked: draft an allowlist request
                                          with the evidence pre-filled
```

**Key design property — fail closed.** If a bound proxy is unreachable, Firefox
fails the request. It never silently falls back to your real IP. Requests with no
tab identity (extension/system traffic) go direct and are never routed through a
program's proxy.

## Quick start

**Extension** (Firefox):
```
about:debugging#/runtime/this-firefox → Load Temporary Add-on → hunt-containers/manifest.json
```
Enable containers first: set `privacy.userContext.enabled = true` in `about:config`.
See [`hunt-containers/README.md`](hunt-containers/README.md) for the full model and a
two-identity preset walkthrough.

**CLI**:
```bash
cd proxycheck
pip install -r requirements.txt
cp proxies.txt.example proxies.txt          # fill with your own proxies

python3 proxycheck.py inventory -f proxies.txt              # fleet health, no target contact
python3 proxycheck.py diagnose --url https://target/api --proxy socks5h://...
```
See [`proxycheck/README.md`](proxycheck/README.md).

## What this deliberately does **not** do

No User-Agent rotation, no `navigator.webdriver` stripping, no "burned IP"
tracking, no sweeping a proxy list against a target to find an unblocked address.
That is an evasion loop, and evading a target's anti-abuse layer is outside what a
bug bounty scope authorizes. When an in-scope test is blocked at the edge, the
supported fix is a **program allowlist** — which is exactly the evidence
`proxycheck diagnose` is built to produce.

## Limitations (read before relying on it)

- **Per-tab routing is Firefox-only.** Chrome's MV3 cannot do per-tab proxying,
  containers, SOCKS5-with-auth, or blocking `webRequest`. On Chrome the extension
  degrades to a single global proxy with no isolation and no marker headers — and
  it says so in a banner rather than pretending.
- **It is a routing/isolation layer, not a proxy pool.** It routes through proxies
  you supply. It does not provision, rotate, or load-balance them. A managed
  rotating backend would be a separate build.
- **Temporary install.** A temporary add-on clears on Firefox restart; a
  persistent install needs AMO signing (`web-ext sign --channel=unlisted`) or
  Developer Edition with `xpinstall.signatures.required=false`.
- **Third-party geo.** `proxycheck` uses `ip-api.com` for geo/ASN and
  proxy/datacenter classification; `--no-geo` disables it. Concurrency defaults to
  a deliberately low 4.

## License

MIT — see [LICENSE](LICENSE).
