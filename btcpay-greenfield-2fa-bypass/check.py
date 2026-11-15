#!/usr/bin/env python3
# Author: al4n4n (Dadb0d)
"""
check.py - Non-destructive detector for the BTCPay Server Greenfield API
TOTP 2FA bypass (PR #7491, fixed in v2.4.2).

SAFE FOR PRODUCTION. It sends a single read-only GET /api/v1/users/me with HTTP
Basic auth and reads the verdict from the response. It never changes state, never
brute-forces, never triggers a destructive action.

Because the bug lives behind authentication, the definitive test needs credentials
for an account that HAS TOTP (authenticator-app) 2FA enabled. Supply them with
--user / --password. The logic:

  * HTTP 200                                              -> VULNERABLE
        Basic auth authenticated a 2FA account with no TOTP code (the bypass).
  * HTTP 401 "...multi-factor is enabled."                -> NOT VULNERABLE (patched)
  * HTTP 401 "...Basic authentication ... is not enabled" -> NOT VULNERABLE (patched/#7492)
  * HTTP 401 "...Rate limited..."                         -> UNKNOWN (throttled, retry)
  * anything else                                         -> UNKNOWN

Exit codes: 0 = vulnerable, 1 = not vulnerable, 2 = unknown. Supports --json.
Stdlib only.
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.request

ME = "/api/v1/users/me"
PATCHED_2FA = "cannot use basic authentication when multi-factor is enabled"
PATCHED_OPTIN = "basic authentication for the greenfield api is not enabled"
THROTTLED = "rate limited"


def http_get(url, path, auth=None, timeout=15):
    req = urllib.request.Request(url.rstrip("/") + path)
    req.add_header("Accept", "application/json")
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def detect(url, user, password):
    # 1. confirm the Greenfield API is present (unauthenticated probe).
    code, body = http_get(url, ME)
    if code is None:
        return "unknown", "low", f"target unreachable: {body}", None
    if code != 401:
        return "unknown", "low", f"{ME} unauth returned HTTP {code} (not a Greenfield API?)", code

    if not (user and password):
        return ("unknown", "low",
                "Greenfield API present. Supply --user/--password for a TOTP-2FA "
                "account to confirm.", code)

    # 2. definitive credentialed, read-only probe.
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    code, body = http_get(url, ME, auth)
    low = body.lower()
    if code == 200:
        return "vulnerable", "high", "Basic auth authenticated the account with no 2FA factor.", code
    if code == 401 and (PATCHED_2FA in low or PATCHED_OPTIN in low):
        return "not_vulnerable", "high", "Patched handler rejected Basic auth for the 2FA account.", code
    if code == 401 and THROTTLED in low:
        return "unknown", "low", "Rate limited by the login throttle; retry later.", code
    if code == 401:
        return ("unknown", "low",
                "Basic auth failed (bad credentials, or account not enabled/approved). "
                f"body: {body[:120]}", code)
    return "unknown", "low", f"unexpected HTTP {code}: {body[:120]}", code


def main():
    ap = argparse.ArgumentParser(description="Non-destructive BTCPay Greenfield 2FA-bypass check")
    ap.add_argument("--url", default="http://127.0.0.1:8080", help="target base URL")
    ap.add_argument("--user", help="email of a TOTP-2FA-enabled account")
    ap.add_argument("--password", help="password of that account")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    verdict, confidence, reason, status = detect(args.url, args.user, args.password)

    out = {"url": args.url, "endpoint": ME, "http_status": status,
           "verdict": verdict, "confidence": confidence, "reason": reason}
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        label = {"vulnerable": "[+] VULNERABLE",
                 "not_vulnerable": "[-] NOT VULNERABLE",
                 "unknown": "[?] UNKNOWN"}[verdict]
        print(f"{label} (confidence: {confidence})")
        print(f"    target : {args.url}")
        print(f"    status : HTTP {status}")
        print(f"    reason : {reason}")

    return {"vulnerable": 0, "not_vulnerable": 1, "unknown": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())
