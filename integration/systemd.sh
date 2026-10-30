#!/bin/bash
set -euo pipefail
# This test installs a real service. It must never run directly on a work host.
test "${DERPER_GO_SYSTEMD_TEST:-}" = 1
test -f /opt/derper-go-isolated-test
test -d /run/systemd/system
trap 'systemctl stop derper-go.service derper-go-credential-test.service >/dev/null 2>&1 || true; kill "${occupant:-}" >/dev/null 2>&1 || true' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /opt/test.key -out /opt/test.pem -days 1 -subj /CN=relay.example.com \
  -addext subjectAltName=DNS:relay.example.com \
  -addext basicConstraints=critical,CA:FALSE -addext extendedKeyUsage=serverAuth
openssl s_server -accept 443 -cert /opt/test.pem -key /opt/test.key -quiet >/tmp/port-443.log 2>&1 &
occupant=$!
for attempt in {1..50}; do
  if (echo >/dev/tcp/127.0.0.1/443) 2>/dev/null; then break; fi
  sleep 0.1
done
mkdir -p /etc/derper-go
cat >/etc/derper-go/config.json <<'JSON'
{
  "domain": "relay.example.com",
  "access": "public",
  "certificate": {"file": "/opt/test.pem", "key": "/opt/test.key"},
  "dns": {"publish": false}
}
JSON
/opt/derper-go init --yes
test "$(systemctl show derper-go.service -p Type --value)" = notify
test "$(systemctl show derper-go.service -p ActiveState --value)" = active
test "$(systemctl show derper-go.service -p User --value)" = derper-go
test "$(stat -c '%a:%U' /var/lib/derper-go)" = 700:derper-go
test "$(stat -c '%a:%U:%G' /etc/derper-go/config.json)" = 640:root:derper-go
test "$(stat -c '%a:%U:%G' /etc/derper-go/certificate.key)" = 640:root:derper-go
jq -e '.port == 8443 and .certificate.file == "certificate.pem"' /etc/derper-go/config.json
derper-go status --json | jq -e '.active and .ready and .certificate.state == "ready" and .dns.state == "disabled" and .tailnet.state == "public"'
derper-go tailnet config | jq -e '.derpMap.regions["900"].Nodes[0].DERPPort == 8443'
identity=$(sha256sum /var/lib/derper-go/identity.json)
configuration=$(sha256sum /etc/derper-go/config.json)
pid=$(systemctl show derper-go.service -p MainPID --value)
derper-go service restart
test "$pid" != "$(systemctl show derper-go.service -p MainPID --value)"
test "$identity" = "$(sha256sum /var/lib/derper-go/identity.json)"
derper-go init --yes
test "$identity" = "$(sha256sum /var/lib/derper-go/identity.json)"
test "$configuration" = "$(sha256sum /etc/derper-go/config.json)"
# A changed low port must update the generated unit, not only reload JSON.
kill "$occupant"
wait "$occupant" || true
occupant=
jq '.port = 443' /etc/derper-go/config.json > /tmp/updated-config.json
cat /tmp/updated-config.json > /etc/derper-go/config.json
derper-go service restart
systemctl show derper-go.service -p AmbientCapabilities --value | grep -q cap_net_bind_service
test "$identity" = "$(sha256sum /var/lib/derper-go/identity.json)"
# Validate the actual TLS listener with a local trust root.
printf 'GET /derp/probe HTTP/1.1\r\nHost: relay.example.com\r\nConnection: close\r\n\r\n' |
  openssl s_client -quiet -connect 127.0.0.1:443 -servername relay.example.com \
    -CAfile /etc/derper-go/certificate.pem -verify_return_error > /tmp/probe.txt
# grep is available in the minimal test image; no ripgrep dependency is needed.
grep -q 'HTTP/1.1 200' /tmp/probe.txt
derper-go service stop
derper-go status --json | jq -e '.active == false and .ready == false'
derper-go service start
derper-go status --json | jq -e '.active and .ready'
systemctl is-enabled --quiet derper-go.service
# Exercise systemd's credential parser with the rendered unit. Syntax validation
# alone accepts quoted LoadCredential values but then treats quotes literally.
# A root-only fixture catches accidental dependence on the service being able
# to read the source file. The program rejects whitespace in credential paths.
printf 'test credential\n' > /opt/expected-credential
chmod 0644 /opt/expected-credential
install -m 0600 /opt/expected-credential /etc/derper-go/test-credentials.token
jq '.dns.publish = true | .cloudflare.token_file = "/etc/derper-go/test-credentials.token"' \
  /etc/derper-go/config.json > /opt/credential-config.json
derper-go service render -c /opt/credential-config.json |
  sed -e 's/^Type=notify$/Type=oneshot/' \
      -e 's#^ExecStart=.*#ExecStart=/usr/bin/cmp %d/cloudflare-token /opt/expected-credential#' \
      -e 's/^Restart=on-failure$/Restart=no/' \
      > /etc/systemd/system/derper-go-credential-test.service
systemctl daemon-reload
systemctl start derper-go-credential-test.service
test "$(systemctl show derper-go-credential-test.service -p Result --value)" = success
test "$(stat -c '%a:%U' /etc/derper-go/test-credentials.token)" = 600:root
printf 'Isolated systemd installation, readiness, credentials, restart and identity checks passed.\n'
