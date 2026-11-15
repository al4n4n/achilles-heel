#!/usr/bin/env python3
# Author: al4n4n (Dadb0d)
"""
setup.py - Lab environment for the BTCPay Server Greenfield API TOTP 2FA bypass
(PR #7491, fixed in v2.4.2).

Boots two BTCPay Server containers behind one PostgreSQL container:

    btcpay241  (btcpayserver/btcpayserver:2.4.1)  -> VULNERABLE   host port 8080
    btcpay242  (btcpayserver/btcpayserver:2.4.2)  -> FIXED        host port 8081

and provisions, on EACH, an admin account with real TOTP (authenticator-app) 2FA
enabled and NO FIDO2 key -- the exact precondition the vulnerable handler fails to
check. Enrollment is done through the real web flow: register -> login -> GET
/account/enableauthenticator -> submit a freshly computed TOTP code. No credential
or exploit logic lives in poc.py; this script does all the authenticated setup.

On the FIXED target it also sets the per-user AllowGreenfieldBasicAuth opt-in
(PR #7492) so the negative control deterministically exercises the PR #7491 2FA
gate ("Cannot use Basic authentication when multi-factor is enabled.") instead of
the opt-in gate.

    python3 setup.py                 # pull (if needed), boot, provision
    python3 setup.py --skip-boot     # re-provision only (containers already up)
    python3 setup.py --teardown      # remove containers + network

Requires: docker, python3 (stdlib only). The host must be able to reach the
container ports. Default host ports are 8080/8081; override with --vuln-port /
--fixed-port if those are taken.
"""
import argparse
import base64
import hashlib
import hmac
import html as htmlmod
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NET = "btcpaylab"
PG = "btcpay-pg"
PG_USER = "btcpay"
PG_PASS = "btcpay"
VULN = {"name": "btcpay241", "image": "btcpayserver/btcpayserver:2.4.1", "db": "btcpay241"}
FIXED = {"name": "btcpay242", "image": "btcpayserver/btcpayserver:2.4.2", "db": "btcpay242"}


def sh(args, check=True, capture=True):
    r = subprocess.run(args, text=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    if check and r.returncode != 0:
        print(f"[!] command failed: {' '.join(args)}\n{r.stdout}")
        sys.exit(1)
    return r.stdout or ""


def image_present(image):
    return bool(sh(["docker", "images", "-q", image], check=False).strip())


# --------------------------------------------------------------------------- #
# HTTP provisioning (stdlib only)
# --------------------------------------------------------------------------- #
class Session:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cj = urllib.request.HTTPCookieProcessor()
        self.op = urllib.request.build_opener(self.cj)
        self.op.addheaders = [("User-Agent", "btcpay-lab-setup")]

    def req(self, path, data=None):
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            r = urllib.request.Request(self.base + path, data=body, method="POST")
            r.add_header("Content-Type", "application/x-www-form-urlencoded")
        else:
            r = urllib.request.Request(self.base + path)
        try:
            with self.op.open(r, timeout=30) as resp:
                return resp.getcode(), resp.read().decode("utf-8", "replace"), resp.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), self.base + path


def _tok(h):
    m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', h)
    return m.group(1) if m else None


def _field(h, name):
    m = (re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(name), h)
         or re.search(r'value="([^"]*)"[^>]*name="%s"' % re.escape(name), h))
    return htmlmod.unescape(m.group(1)) if m else None


def _totp(shared_key, step=30, digits=6):
    s = shared_key.upper().replace(" ", "")
    key = base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))
    msg = struct.pack(">Q", int(time.time() // step))
    d = hmac.new(key, msg, hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return str((struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)).zfill(digits)


def wait_ready(base, timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = Session(base)
            code, _, _ = s.req("/login")
            if code == 200:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(3)
    return False


def provision(base, email, password):
    """Create the first (admin) user and enable real TOTP 2FA. Idempotent."""
    s = Session(base)
    # register (first user becomes ServerAdmin). If it already exists -> /login.
    _, h, _ = s.req("/register")
    s.req("/register", {"__RequestVerificationToken": _tok(h), "Email": email,
                        "Password": password, "ConfirmPassword": password})
    # login
    _, h, _ = s.req("/login")
    _, h, url = s.req("/login", {"__RequestVerificationToken": _tok(h), "Email": email,
                                 "Password": password, "RememberMe": "false", "Method": "Password"})
    if "second-login" in url:
        return "already-2fa"            # 2FA already on -> browser demands 2nd factor
    # enroll TOTP
    code, h, _ = s.req("/account/enableauthenticator")
    if code != 200:
        return f"enroll-unreachable:{code}"
    sk = _field(h, "SharedKey")
    uri = _field(h, "AuthenticatorUri")
    _, h, _ = s.req("/account/enableauthenticator", {
        "__RequestVerificationToken": _tok(h), "SharedKey": sk, "AuthenticatorUri": uri,
        "Code": _totp(sk), "HideSensitiveInfo": "false"})
    _, h2, _ = s.req("/account/twofactorauthentication")
    return "enabled" if "disable" in h2.lower() else "enroll-failed"


def enable_basic_auth_optin(db, email):
    """Set the PR #7492 per-user opt-in so the negative control hits the 2FA gate."""
    sql = ("UPDATE \"AspNetUsers\" SET \"Blob2\" = "
           "COALESCE(\"Blob2\",'{}'::jsonb) || '{\"allowGreenfieldBasicAuth\": true}'::jsonb "
           f"WHERE \"Email\"='{email}';")
    sh(["docker", "exec", PG, "psql", "-U", PG_USER, "-d", db, "-c", sql], check=False)


# --------------------------------------------------------------------------- #
# Docker lab
# --------------------------------------------------------------------------- #
def boot(args):
    for spec in (VULN, FIXED):
        if not image_present(spec["image"]):
            print(f"[*] pulling {spec['image']} ...")
            sh(["docker", "pull", spec["image"]], capture=False)

    sh(["docker", "network", "create", NET], check=False)

    print("[*] starting PostgreSQL ...")
    sh(["docker", "rm", "-f", PG], check=False)
    sh(["docker", "run", "-d", "--name", PG, "--network", NET,
        "-e", f"POSTGRES_USER={PG_USER}", "-e", f"POSTGRES_PASSWORD={PG_PASS}",
        "-e", f"POSTGRES_DB={VULN['db']}", "postgres:16-alpine"])
    # wait for pg
    for _ in range(30):
        if "accepting connections" in sh(["docker", "exec", PG, "pg_isready", "-U", PG_USER], check=False):
            break
        time.sleep(2)
    sh(["docker", "exec", PG, "psql", "-U", PG_USER, "-d", VULN["db"],
        "-c", f"CREATE DATABASE {FIXED['db']};"], check=False)

    for spec, port in ((VULN, args.vuln_port), (FIXED, args.fixed_port)):
        print(f"[*] starting {spec['name']} ({spec['image']}) on host port {port} ...")
        sh(["docker", "rm", "-f", spec["name"]], check=False)
        sh(["docker", "run", "-d", "--name", spec["name"], "--network", NET,
            "-p", f"127.0.0.1:{port}:8080",
            "-e", "BTCPAY_NETWORK=regtest", "-e", "BTCPAY_BIND=0.0.0.0", "-e", "BTCPAY_PORT=8080",
            "-e", f"BTCPAY_POSTGRES=User ID={PG_USER};Password={PG_PASS};Host={PG};Port=5432;Database={spec['db']}",
            spec["image"]])


def teardown():
    for n in (VULN["name"], FIXED["name"], PG):
        sh(["docker", "rm", "-f", n], check=False)
    sh(["docker", "network", "rm", NET], check=False)
    print("[*] lab removed.")


def main():
    ap = argparse.ArgumentParser(description="BTCPay Greenfield 2FA-bypass lab setup")
    ap.add_argument("--vuln-port", type=int, default=8080)
    ap.add_argument("--fixed-port", type=int, default=8081)
    ap.add_argument("--email", default="admin@lab.local")
    ap.add_argument("--password", default="Lab-Passw0rd!2026")
    ap.add_argument("--skip-boot", action="store_true", help="only (re)provision; containers already up")
    ap.add_argument("--teardown", action="store_true", help="remove lab and exit")
    args = ap.parse_args()

    if args.teardown:
        teardown()
        return 0

    if not args.skip_boot:
        boot(args)

    vuln_url = f"http://127.0.0.1:{args.vuln_port}"
    fixed_url = f"http://127.0.0.1:{args.fixed_port}"

    for label, url, spec in (("VULNERABLE 2.4.1", vuln_url, VULN), ("FIXED 2.4.2", fixed_url, FIXED)):
        print(f"[*] waiting for {label} at {url} ...")
        if not wait_ready(url):
            print(f"[!] {label} did not become ready in time.")
            return 1
        res = provision(url, args.email, args.password)
        print(f"[*] {label} provisioning: {res}")

    # isolate the PR #7491 2FA gate for the negative control on the fixed target
    enable_basic_auth_optin(FIXED["db"], args.email)
    print("[*] enabled AllowGreenfieldBasicAuth on the fixed target (isolates PR #7491 gate)")

    print("\n" + "=" * 70)
    print(" LAB READY")
    print("=" * 70)
    print(f"   vulnerable : {vuln_url}   (btcpayserver 2.4.1)")
    print(f"   fixed      : {fixed_url}   (btcpayserver 2.4.2)")
    print(f"   account    : {args.email} / {args.password}   (TOTP 2FA enabled, no FIDO2)")
    print("\n   # non-destructive check")
    print(f"   python3 check.py  --url {vuln_url} --user {args.email} --password '{args.password}'")
    print("\n   # single-shot exploit")
    print(f"   python3 poc.py    --url {vuln_url} --user {args.email} --password '{args.password}'")
    print("\n   # verification dashboard with negative control")
    print(f"   python3 verify.py --url {vuln_url} --fixed-url {fixed_url} \\")
    print(f"                     --user {args.email} --password '{args.password}' --rounds 5")
    return 0


if __name__ == "__main__":
    sys.exit(main())
