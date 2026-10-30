#!/bin/bash
set -euo pipefail
# This modifies systemd only on an ephemeral GitHub-hosted runner. Docker's
# credential mounts can be absent even when a unit starts successfully.
test "${GITHUB_ACTIONS:-}" = true
test "${DERPER_GO_SYSTEMD_TEST:-}" = 1
test "$(id -u)" = 0
test -d /run/systemd/system
test "$#" = 1
binary=$1
work=$(mktemp -d /run/derper-go-credential-test.XXXXXX)
state_name=${work##*/}
unit=$state_name.service
cleanup() {
  result=$?
  if test "$result" != 0; then
    journalctl -u "$unit" --no-pager || true
    systemctl cat "$unit" || true
  fi
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  rm -f "/run/systemd/system/$unit"
  rm -rf "/run/systemd/system/$unit.d"
  systemctl daemon-reload
  rm -rf "$work" "/var/lib/$state_name"
  exit "$result"
}
trap cleanup EXIT
chmod 0755 "$work"
printf 'test credential\n' > "$work/expected"
chmod 0644 "$work/expected"
install -m 0600 "$work/expected" "$work/cloudflare.token"
runuser -u nobody -- test ! -r "$work/cloudflare.token"
cat > "$work/check" <<'SH'
#!/bin/sh
set -eu
test -n "${CREDENTIALS_DIRECTORY:-}"
exec /usr/bin/cmp "$CREDENTIALS_DIRECTORY/cloudflare-token" "${0%/*}/expected"
SH
chmod 0755 "$work/check"
jq -n --arg token "$work/cloudflare.token" \
  '{domain:"relay.example.com",email:"ops@example.com",access:"public",cloudflare:{token_file:$token}}' \
  > "$work/config.json"
"$binary" service render -c "$work/config.json" |
  sed -e 's/^Type=notify$/Type=oneshot/' \
      -e "s#^ExecStart=.*#ExecStart=$work/check#" \
      -e 's/^Restart=on-failure$/Restart=no/' \
      -e 's/^User=derper-go$/User=nobody/' \
      -e 's/^Group=derper-go$/Group=nogroup/' \
      -e "s/^StateDirectory=derper-go$/StateDirectory=$state_name/" \
      -e "s/^RuntimeDirectory=derper-go$/RuntimeDirectory=$state_name-runtime/" \
      > "/run/systemd/system/$unit"
grep -Fx "LoadCredential=cloudflare-token:$work/cloudflare.token" "/run/systemd/system/$unit"
systemctl daemon-reload
systemctl start "$unit"
test "$(systemctl show "$unit" -p Result --value)" = success
test "$(stat -c '%a:%U' "$work/cloudflare.token")" = 600:root
# Verify the v0.1.0 gz credential override remains compatible during upgrade.
mkdir -p "/run/systemd/system/$unit.d"
printf '[Service]\nLoadCredential=\nLoadCredential=cloudflare-token:%s/cloudflare.token\n' "$work" > "/run/systemd/system/$unit.d/10-credentials.conf"
systemctl daemon-reload
systemctl start "$unit"
test "$(systemctl show "$unit" -p Result --value)" = success
printf 'Rendered systemd unit loaded the root-only credential successfully.\n'
