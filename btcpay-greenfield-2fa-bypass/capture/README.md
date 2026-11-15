# Exploit capture

`exploit.pcap` is a **live capture** of the TOTP 2FA bypass against
`btcpayserver/btcpayserver:2.4.1`. It was recorded with `tcpdump` running inside the
target container's network namespace while `poc.py` ran on the host and the Docker
bridge NAT'd the request into the container.

## How it was captured

```bash
# tcpdump sidecar sharing the vulnerable container's network namespace
docker run -d --name btcpaycap --network container:btcpay241 -v "$PWD/capture":/out alpine \
  sh -c "apk add --no-cache tcpdump && tcpdump -i eth0 -s 0 -U -w /out/exploit.pcap 'tcp port 8080'"

# real exploit traffic (identical to poc.py)
python3 poc.py --url http://127.0.0.1:18080 --user admin@lab.local --password 'Lab-Passw0rd!2026'

docker stop btcpaycap
```

- **Type:** live capture (tcpdump), not synthetic / not scapy-generated.
- **Transport:** cleartext HTTP (no TLS) so the `Authorization: Basic` header and the
  JSON responses are visible to an IDS.
- **Packets:** 50.
- **Addresses (RFC 1918, distinct):** `172.19.0.1` (Docker bridge gateway, client side,
  NAT source of the host's `poc.py`) -> `172.19.0.3` (the `btcpay241` container, port 8080).
- **Contents:** five Greenfield API requests, each carrying
  `Authorization: Basic YWRtaW5AbGFiLmxvY2FsOkxhYi1QYXNzdzByZCEyMDI2`
  (`admin@lab.local:Lab-Passw0rd!2026`):
  - `GET /api/v1/users/me`        -> `200 OK`  (bypass: TOTP account authenticated)
  - `GET /api/v1/users`           -> `200 OK`  (all users; server-admin scope)
  - `GET /api/v1/stores`          -> `200 OK`
  - `GET /api/v1/server/info`     -> `500`     (reachable; errors in the minimal lab)
  - `GET /api/v1/server/lightning/BTC/info` -> `404 lightning-not-configured` (reachable)

No TOTP code, FIDO2 assertion, or API key is present anywhere in the capture.

## Verify the detection rules against the capture

```bash
suricata -r capture/exploit.pcap -S detection/btcpay-greenfield-2fa-bypass.rules -l /tmp/suri -k none
cat /tmp/suri/fast.log
```

Expected (validated with `jasonish/suricata`): SID `9100001` and `9100002` fire on every
Basic-auth request. SID `9100003` (patched-server rejection message) fires instead on a
capture taken against v2.4.2, where the response body is
`"Cannot use Basic authentication when multi-factor is enabled."`

## Note on production traffic

Real BTCPay deployments terminate TLS at a reverse proxy, so on the public leg this traffic
is encrypted. These rules are for the plaintext leg behind the proxy, an internal HTTP
listener, or mirrored/decrypted traffic. For log-based detection on a TLS deployment, use
the Sigma rules in `detection/` against the proxy access log.
