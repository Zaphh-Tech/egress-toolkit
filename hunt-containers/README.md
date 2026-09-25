# Hunt Containers

Per-container egress proxy + isolated cookie jars + program-mandated marker headers,
for authorized bug bounty testing.

## Why Firefox

This is the part worth reading before you install.

| Requirement            | Chrome MV3                                  | Firefox MV3 |
|------------------------|---------------------------------------------|-------------|
| Per-tab proxy          | **Impossible.** `chrome.proxy` is browser-global; PAC scripts route by host, and a PAC has no tab identity. | `proxy.onRequest` gives you `tabId` per request. Works. |
| Cookie isolation       | **Impossible.** No container API; needs separate `--profile-directory` processes. | `contextualIdentities` = real separate cookie jars. Works. |
| SOCKS5 with auth       | Not supported by Chrome at all.             | Supported. |
| Blocking `webRequest`  | Removed in MV3 (declarativeNetRequest only).| Retained. Header injection works. |

So: install in Firefox. The extension detects Chrome and degrades to a single
global proxy with no isolation, and says so in a banner rather than pretending.
On Chrome you additionally lose the marker headers (`webRequestBlocking` does not
exist in Chrome MV3) — Chrome loads the extension with a permission warning and
those listeners simply never fire.

## Install (Firefox)

    about:debugging#/runtime/this-firefox  ->  Load Temporary Add-on  ->  pick manifest.json

Temporary add-ons clear on restart. For a persistent install, sign it via AMO
(`web-ext sign --channel=unlisted`) or run Firefox Developer Edition with
`xpinstall.signatures.required=false`.

Containers must be enabled: `privacy.userContext.enabled = true` in `about:config`.

## Model

    request -> tabId -> tab binding        (popup dropdown, session only)
            -> tabId -> container binding  (options page, persisted)
            -> neither -> DIRECT

Unbound tabs go direct. Requests with no tab (extension/system traffic) go direct
— they are never routed through a program's proxy.

**Leak behaviour:** if a bound proxy is unreachable, Firefox fails the request. It
does not silently fall back to your real IP. That is deliberate and is the main
reason to bind at the container level rather than juggling system proxy settings.

**DNS:** `proxyDNS` is on by default for SOCKS. Without it your resolver sees every
target hostname even though the traffic is proxied.

## Headers

Per-profile static headers exist for one job: program-mandated markers. Most
programs that hand out a WAF allowlist require an identifying header on every
request as the condition. Put it on the profile and it rides every request in
that container automatically, so you cannot forget it mid-session.

Set them one per line: `X-Bug-Bounty: your-handle`

## Two-identity preset (worked example)

Authorization testing often needs two accounts live in mutually invisible
sessions at the same time — account A's object and account B's credential, in
one browser. A preset makes that a one-click launch.

1. Options -> Proxy profiles -> add your egress, note the program in Notes.
2. Options -> Presets:
   - Name `Target — account A`, Container `acct-a`, URL the login page, proxy = your profile
   - Name `Target — account B`, Container `acct-b`, URL the same, proxy = same or different
3. Popup -> launch. Each opens in its own cookie jar. Log in as A in one, B in the
   other. They cannot see each other's session, and neither can leak into your
   normal browsing.

This is what makes cross-account authorization checks (BOLA/IDOR, tenant
isolation, `private`/`public` path-segment authz) reproducible: both identities
are live simultaneously and provably isolated.

## Not included

No User-Agent randomization, no `navigator.webdriver` stripping, no WAF-block
probe loop. If CloudFront is blocking you on an in-scope target, ask the program
for an IP allowlist — that is a supported request on both HackerOne and
HackenProof, it is permanent, and it does not put you in the position of having
your traffic look identical to the abuse their WAF exists to stop.

## Verify it works

Popup -> `test` next to a profile. It opens a throwaway background tab bound to
that profile, reads the echoed egress IP through the real route, and closes it.
If the IP shown is not the proxy's, the binding is not applied.
