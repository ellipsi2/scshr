#!/usr/bin/env bash
# Static tests for tools/scshr-macos-tunnel.sh — runnable anywhere bash exists (no macOS needed).
#
# Checks shell syntax, the generated WireGuard config and PF anchor against goldens, and the
# strict decoding of pairing descriptors. The SCST1/SCCL1 goldens are the same strings the C++
# encoder produces in tests/test_tunnel.cpp, so the two implementations are cross-checked.
#
#   bash tests/tunnel_shell_test.sh
set -uo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
sh="${here}/tools/scshr-macos-tunnel.sh"
gold="${here}/testdata/tunnel"
fail=0
run=0

MAC_PUB="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
WIN_PUB="AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw="
SERVER_CODE="SCST1:az1BQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4PQplPW15LW1hYy5leGFtcGxlLm5ldApwPTUxODIwCnM9MTAuNzcuNzcuMQpjPTEwLjc3Ljc3LjI"
CLIENT_CODE="SCCL1:az1Bd29SR0I4bUxUUTdRa2xRVjE1bGJITjZnWWlQbHAya3E3SzV3TWZPMWR3PQpjPTEwLjc3Ljc3LjI"

ok()   { run=$((run+1)); printf 'PASS %s\n' "$1"; }
bad()  { run=$((run+1)); fail=$((fail+1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

expect_eq() {   # <name> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi
}
expect_file() {   # <name> <golden> <actual-text>
    if printf '%s\n' "$3" | diff -u "$2" - >/dev/null 2>&1; then ok "$1"; else
        bad "$1" "output differs from $2"
        printf '%s\n' "$3" | diff -u "$2" - | sed 's/^/    /'
    fi
}
expect_reject() {   # <name> <args...>
    if out="$("$sh" "${@:2}" 2>&1)"; then bad "$1" "accepted invalid input: $out"; else ok "$1"; fi
}

# ── syntax ────────────────────────────────────────────────────────────────────────────────────
if bash -n "$sh" 2>/dev/null; then ok "shell_syntax"; else bad "shell_syntax" "bash -n failed"; fi

# ── generation goldens ────────────────────────────────────────────────────────────────────────
expect_file "macos_conf_generation" "${gold}/macos.conf" \
    "$("$sh" render-conf "$WIN_PUB" 10.77.77.1 51820 "$MAC_PUB" 10.77.77.2)"
expect_file "macos_conf_generation_unpaired" "${gold}/macos-unpaired.conf" \
    "$("$sh" render-conf "$WIN_PUB" 10.77.77.1 51820)"
expect_file "pf_anchor_generation" "${gold}/pf-anchor" \
    "$("$sh" render-pf 10.77.77.1 10.77.77.2 51820)"

# The generated config must never widen the tunnel or touch the resolver.
conf="$("$sh" render-conf "$WIN_PUB" 10.77.77.1 51820 "$MAC_PUB" 10.77.77.2)"
case "$conf" in
    *0.0.0.0/0*|*::/0*|*DNS*|*Table*) bad "macos_conf_route_policy" "config widens the tunnel or sets DNS" ;;
    *) ok "macos_conf_route_policy" ;;
esac

# ── launchd + preflight contract ──────────────────────────────────────────────────────────────
expect_file "launchd_plist_generation" "${gold}/net.scshr.tunnel.plist" \
    "$("$sh" render-plist /usr/local/libexec/scshr-macos-tunnel.sh)"

# The daemon must supervise the tunnel itself: a crashed helper has to be restarted, not left down
# while the machine believes the tunnel is running.
plist="$("$sh" render-plist /usr/local/libexec/scshr-macos-tunnel.sh)"
case "$plist" in
    *"<key>KeepAlive</key><true/>"*) ok "launchd_plist_keepalive" ;;
    *) bad "launchd_plist_keepalive" "the LaunchDaemon does not set KeepAlive" ;;
esac

# The Windows wizard parses exactly these keys out of `preflight`.
expect_eq "preflight_keys" "macos_version
arch
helper
pf_conf
screen_sharing
sudo
firewall" "$("$sh" render-preflight-keys)"

# The Mac side must be self-contained: stock macOS plus the uploaded files, so nothing may depend
# on Homebrew wireguard-tools or on a bash newer than the 3.2 macOS ships.
script_text="$(cat "$sh")"
case "$script_text" in
    *wg-quick*|*"brew install"*|*BASH_VERSINFO*)
        bad "no_wireguard_tools_dependency" "the script still needs wireguard-tools or bash 4+" ;;
    *) ok "no_wireguard_tools_dependency" ;;
esac

# ── descriptor encoding cross-check against the C++ encoder ───────────────────────────────────
expect_eq "server_code_matches_cxx_golden" "$SERVER_CODE" \
    "$("$sh" render-server-code "$MAC_PUB" my-mac.example.net 51820 10.77.77.1 10.77.77.2)"
expect_eq "client_code_matches_cxx_golden" "$CLIENT_CODE" \
    "$("$sh" render-client-code "$WIN_PUB" 10.77.77.2)"
expect_eq "client_code_roundtrip" "$WIN_PUB 10.77.77.2" "$("$sh" decode-client-code "$CLIENT_CODE")"

# Descriptors must not be able to carry private material: the payload is exactly two fields.
body="$(printf '%s' "${CLIENT_CODE#SCCL1:}" | tr -- '-_' '+/' | { read -r s; case $(( ${#s} % 4 )) in (2) s="${s}==";; (3) s="${s}=";; esac; printf '%s' "$s"; } | base64 --decode 2>/dev/null || true)"
expect_eq "client_code_payload_is_public_only" "k=${WIN_PUB}
c=10.77.77.2" "$body"

# ── strict rejection ──────────────────────────────────────────────────────────────────────────
expect_reject "reject_unsupported_version"      decode-client-code "SCCL2:${CLIENT_CODE#SCCL1:}"
expect_reject "reject_wrong_descriptor_type"    decode-client-code "$SERVER_CODE"
expect_reject "reject_empty_descriptor"         decode-client-code "SCCL1:"
expect_reject "reject_bad_base64url"            decode-client-code "SCCL1:!!!!"
expect_reject "reject_padded_base64"            decode-client-code "SCCL1:${CLIENT_CODE#SCCL1:}="
b64url() { base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='; }
expect_reject "reject_bad_key_in_descriptor"    decode-client-code "SCCL1:$(printf 'k=nope\nc=10.77.77.2' | b64url)"
expect_reject "reject_outside_subnet"           decode-client-code "SCCL1:$(printf 'k=%s\nc=192.168.1.2' "$WIN_PUB" | b64url)"
expect_reject "reject_default_route_address"    render-client-code "$WIN_PUB" 0.0.0.0
expect_reject "reject_broad_subnet_address"     render-client-code "$WIN_PUB" 10.0.0.1
expect_reject "reject_invalid_key"              render-client-code "not-a-key" 10.77.77.2
expect_reject "reject_invalid_endpoint"         render-server-code "$MAC_PUB" "bad host" 51820 10.77.77.1 10.77.77.2
expect_reject "reject_multicast_endpoint"       render-server-code "$MAC_PUB" 239.1.2.3 51820 10.77.77.1 10.77.77.2
expect_reject "reject_loopback_endpoint"        render-server-code "$MAC_PUB" 127.0.0.1 51820 10.77.77.1 10.77.77.2
expect_reject "reject_invalid_port"             render-server-code "$MAC_PUB" mac 70000 10.77.77.1 10.77.77.2
expect_reject "reject_identical_tunnel_ips"     render-server-code "$MAC_PUB" mac 51820 10.77.77.1 10.77.77.1

printf '%d tests, %d failures\n' "$run" "$fail"
[ "$fail" -eq 0 ]
