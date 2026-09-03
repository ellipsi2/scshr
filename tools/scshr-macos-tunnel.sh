#!/bin/bash
# scshr macOS tunnel + Screen Sharing isolation.
#
#   sudo ./tools/scshr-macos-tunnel.sh preflight
#   sudo ./tools/scshr-macos-tunnel.sh init --endpoint my-mac.example.net [--listen-port 51820]
#   sudo ./tools/scshr-macos-tunnel.sh pair 'SCCL1:<windows-code>'
#   sudo ./tools/scshr-macos-tunnel.sh up | down | status
#   sudo ./tools/scshr-macos-tunnel.sh uninstall [--reset-identity]
#
# This is NOT a VPN. It creates one WireGuard peering between this Mac (10.77.77.1) and one paired
# Windows machine (10.77.77.2) and then restricts Screen Sharing so it is reachable only across
# that peering. Nothing here enables forwarding, NAT or routing: the Mac is never an exit node.
#
# Nothing needs to be installed on this Mac. The WireGuard implementation is the single static
# helper binary shipped next to this script (scshr-tunnel-darwin-arm64 / -amd64); there is no
# dependency on Homebrew, wireguard-tools or bash 4 — stock /bin/bash 3.2 runs this.
#
# Everything is idempotent; nothing persistent is mutated before every prerequisite and every
# generated file has been validated, and a failed firewall activation is rolled back.
set -euo pipefail

# ── constants ─────────────────────────────────────────────────────────────────────────────────
TUNNEL_NAME="scshr"
TUNNEL_SUBNET_PREFIX="10.77.77."
DEFAULT_MAC_IP="10.77.77.1"
DEFAULT_WIN_IP="10.77.77.2"
DEFAULT_LISTEN_PORT="51820"

STATE_DIR="/usr/local/etc/scshr"
CONF="${STATE_DIR}/${TUNNEL_NAME}.conf"
PRIV_KEY="${STATE_DIR}/private.key"
PUB_KEY="${STATE_DIR}/public.key"
SETTINGS="${STATE_DIR}/settings"
PF_BACKUP_DIR="${STATE_DIR}/pf-backups"
PF_ANCHOR="/etc/pf.anchors/${TUNNEL_NAME}"
PF_CONF="/etc/pf.conf"
PF_ANCHOR_LINE="anchor \"${TUNNEL_NAME}\""
PF_LOAD_LINE="load anchor \"${TUNNEL_NAME}\" from \"${PF_ANCHOR}\""
LAUNCHD_LABEL="net.scshr.tunnel"
LAUNCHD_PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
INSTALLED_SCRIPT="/usr/local/libexec/scshr-macos-tunnel.sh"
INSTALLED_HELPER="/usr/local/libexec/scshr-tunnel"
TUNNEL_LOG="/var/log/scshr-tunnel.log"
SCREEN_SHARING_PLIST="/System/Library/LaunchDaemons/com.apple.screensharing.plist"
UAPI_SOCKET="/var/run/wireguard/${TUNNEL_NAME}.sock"
UTUN_NAME_FILE="/var/run/scshr-tunnel.utun"
ALF="/usr/libexec/ApplicationFirewall/socketfilterfw"
HELPER=""    # set by find_helper

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Mac-side ports scshr actually uses (src/session/session.h): TCP 5900 control/RFB record layer,
# UDP 5900 audio + RTCP, UDP 5901 video. Screen Sharing itself listens on TCP 5900.
SCSHR_TCP_PORTS="5900"
SCSHR_UDP_PORTS="5900 5901"

die() { printf 'scshr: %s\n' "$*" >&2; exit 1; }
info() { printf 'scshr: %s\n' "$*"; }

# ── small helpers ─────────────────────────────────────────────────────────────────────────────
b64e() { base64 | tr -d '\n'; }
b64d() { if base64 --decode </dev/null >/dev/null 2>&1; then base64 --decode; else base64 -D; fi; }
b64url_encode() { b64e | tr '+/' '-_' | tr -d '='; }
b64url_decode() {
    local s; s="$(cat)"
    case $(( ${#s} % 4 )) in 2) s="${s}==" ;; 3) s="${s}=" ;; 1) return 1 ;; esac
    printf '%s' "$s" | tr -- '-_' '+/' | b64d
}

need_root() { [ "$(id -u)" = "0" ] || die "this command must run as root (use sudo)"; }

# Maps uname -m onto the helper binary suffix used in the uploaded bundle.
helper_arch() {
    case "$(uname -m)" in
        arm64) printf 'arm64' ;;
        x86_64) printf 'amd64' ;;
        *) return 1 ;;
    esac
}

# Locates the WireGuard helper: the uploaded bundle copy first, then the installed one.
# Sets HELPER. There is deliberately no fallback to Homebrew wireguard-tools: a stock Mac has none.
find_helper() {
    local arch bundled
    HELPER=""
    if arch="$(helper_arch)"; then
        bundled="${SCRIPT_DIR}/scshr-tunnel-darwin-${arch}"
        if [ -x "$bundled" ]; then HELPER="$bundled"; return 0; fi
    fi
    if [ -x "$INSTALLED_HELPER" ]; then HELPER="$INSTALLED_HELPER"; return 0; fi
    return 1
}

require_helper() {
    find_helper || die "the scshr tunnel helper for this Mac ($(uname -m)) was not found next to this script or at ${INSTALLED_HELPER}"
}

# ── application firewall ──────────────────────────────────────────────────────────────────────
# The daemon is unsigned, so with the Application Firewall on it is prompted for — and nobody can
# answer a prompt for a LaunchDaemon, which silently drops inbound WireGuard handshakes. Adding the
# helper to the ALF allow list up front is the only way a headless install can work. A Mac with the
# ALF off has no list to add to, and every call there is a harmless no-op.
alf_state() {
    if [ ! -x "$ALF" ]; then printf 'unknown'; return; fi
    case "$("$ALF" --getglobalstate 2>/dev/null)" in
        *enabled*) printf 'on' ;;
        *disabled*) printf 'off' ;;
        *) printf 'unknown' ;;
    esac
}

alf_allow_helper() {
    [ -x "$ALF" ] || return 0
    "$ALF" --add "$INSTALLED_HELPER" >/dev/null 2>&1 || true
    "$ALF" --unblockapp "$INSTALLED_HELPER" >/dev/null 2>&1 || true
    info "application firewall: ${INSTALLED_HELPER} allowed to accept incoming connections"
}

alf_remove_helper() {
    [ -x "$ALF" ] || return 0
    "$ALF" --remove "$INSTALLED_HELPER" >/dev/null 2>&1 || true
}

is_wg_key() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]=$'; }

is_tunnel_ip() {
    case "$1" in
        "${TUNNEL_SUBNET_PREFIX}"*) ;;
        *) return 1 ;;
    esac
    local last="${1#"${TUNNEL_SUBNET_PREFIX}"}"
    printf '%s' "$last" | grep -Eq '^[0-9]{1,3}$' || return 1
    [ "$last" -ge 1 ] 2>/dev/null && [ "$last" -le 254 ]
}

is_port() { printf '%s' "$1" | grep -Eq '^[1-9][0-9]{0,4}$' && [ "$1" -le 65535 ]; }

is_endpoint_host() {
    local h="$1"
    [ -n "$h" ] || return 1
    [ "${#h}" -le 253 ] || return 1
    if printf '%s' "$h" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
        local a b c d; IFS=. read -r a b c d <<EOF
$h
EOF
        for o in "$a" "$b" "$c" "$d"; do [ "$o" -le 255 ] 2>/dev/null || return 1; done
        [ "$a" != "0" ] && [ "$a" != "127" ] && [ "$a" -lt 224 ] || return 1
        return 0
    fi
    printf '%s' "$h" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'
}

# ── generators (pure; used by the tests via the render-* subcommands) ─────────────────────────
render_conf() {   # <private-key> <mac-ip> <listen-port> [<peer-public-key> <peer-ip>]
    printf '%s\n' "# Generated by scshr-macos-tunnel.sh - do not edit by hand."
    printf '%s\n' "# scshr application tunnel: one macOS peer <-> one Windows peer, no forwarding, no NAT."
    printf '%s\n' "[Interface]"
    printf 'PrivateKey = %s\n' "$1"
    printf 'Address = %s/32\n' "$2"
    printf 'ListenPort = %s\n' "$3"
    if [ -n "${4:-}" ]; then
        printf '\n%s\n' "[Peer]"
        printf 'PublicKey = %s\n' "$4"
        # No Endpoint: the Windows peer roams and is learned from its own handshake.
        printf 'AllowedIPs = %s/32\n' "$5"
    fi
}

render_pf() {   # <mac-ip> <win-ip> <listen-port>
    local mac="$1" win="$2" port="$3"
    printf '%s\n' "# Generated by scshr-macos-tunnel.sh - do not edit by hand."
    printf '%s\n' "# scshr Screen Sharing isolation. First match wins (quick), so the passes come first."
    printf '%s\n' "# Address-based on purpose: the utun interface number is not stable across boots."
    printf 'pass in quick proto udp from any to any port %s keep state\n' "$port"
    printf 'pass in quick proto tcp from 127.0.0.1 to 127.0.0.1 port { %s } keep state\n' "$SCSHR_TCP_PORTS"
    printf 'pass in quick proto udp from 127.0.0.1 to 127.0.0.1 port { %s } keep state\n' "$SCSHR_UDP_PORTS"
    printf 'pass in quick proto tcp from %s to %s port { %s } keep state\n' "$win" "$mac" "$SCSHR_TCP_PORTS"
    printf 'pass in quick proto udp from %s to %s port { %s } keep state\n' "$win" "$mac" "$SCSHR_UDP_PORTS"
    printf 'block drop in quick proto tcp from any to any port { %s }\n' "$SCSHR_TCP_PORTS"
    printf 'block drop in quick proto udp from any to any port { %s }\n' "$SCSHR_UDP_PORTS"
}

# The daemon runs `<script> run`, which activates PF and then execs the helper. KeepAlive restarts
# it if the helper ever exits, so a crashed tunnel never leaves Screen Sharing unprotected.
render_plist() {   # <installed-script>
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
    printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    printf '%s\n' '<plist version="1.0">'
    printf '%s\n' '<dict>'
    printf '    <key>Label</key><string>%s</string>\n' "$LAUNCHD_LABEL"
    printf '%s\n' '    <key>ProgramArguments</key>'
    printf '%s\n' '    <array>'
    printf '        <string>%s</string>\n' "$1"
    printf '%s\n' '        <string>run</string>'
    printf '%s\n' '    </array>'
    printf '%s\n' '    <key>RunAtLoad</key><true/>'
    printf '%s\n' '    <key>KeepAlive</key><true/>'
    printf '    <key>StandardOutPath</key><string>%s</string>\n' "$TUNNEL_LOG"
    printf '    <key>StandardErrorPath</key><string>%s</string>\n' "$TUNNEL_LOG"
    printf '%s\n' '</dict>'
    printf '%s\n' '</plist>'
}

# The exact key set `preflight` prints, in order. The Windows wizard parses these.
render_preflight_keys() {
    printf '%s\n' macos_version arch helper pf_conf screen_sharing sudo firewall
}

render_server_code() {   # <public-key> <endpoint> <listen-port> <mac-ip> <win-ip>
    is_wg_key "$1" || die "invalid WireGuard public key"
    is_endpoint_host "$2" || die "invalid endpoint host: $2"
    is_port "$3" || die "invalid listen port: $3"
    is_tunnel_ip "$4" || die "invalid mac tunnel IP: $4"
    is_tunnel_ip "$5" || die "invalid windows tunnel IP: $5"
    [ "$4" != "$5" ] || die "tunnel IPs must differ"
    printf 'SCST1:%s' "$(printf 'k=%s\ne=%s\np=%s\ns=%s\nc=%s' "$1" "$2" "$3" "$4" "$5" | b64url_encode)"
    printf '\n'
}

render_client_code() {   # <public-key> <win-ip>   (only used to cross-check the Windows encoder)
    is_wg_key "$1" || die "invalid WireGuard public key"
    is_tunnel_ip "$2" || die "invalid windows tunnel IP: $2"
    printf 'SCCL1:%s' "$(printf 'k=%s\nc=%s' "$1" "$2" | b64url_encode)"
    printf '\n'
}

# Strictly decodes SCCL1 into WIN_PUB / WIN_IP.
decode_client_code() {
    local code="$1" body
    case "$code" in
        SCCL1:*) ;;
        SCCL[0-9]:*|SCCL*:*) die "unsupported pairing descriptor version" ;;
        *) die "not an SCCL1 pairing descriptor" ;;
    esac
    local payload="${code#SCCL1:}"
    [ -n "$payload" ] || die "empty pairing descriptor"
    # The bound is checked separately: BSD grep rejects ERE repetition counts above 255.
    [ "${#payload}" -le 1024 ] || die "pairing descriptor too long"
    printf '%s' "$payload" | grep -Eq '^[A-Za-z0-9_-]+$' || die "invalid base64url payload"
    body="$(printf '%s' "$payload" | b64url_decode)" || die "invalid base64url payload"
    [ "$(printf '%s' "$body" | wc -l | tr -d ' ')" = "1" ] || die "malformed pairing descriptor"
    WIN_PUB="$(printf '%s' "$body" | sed -n '1s/^k=//p')"
    WIN_IP="$(printf '%s' "$body" | sed -n '2s/^c=//p')"
    [ -n "$WIN_PUB" ] || die "malformed pairing descriptor: missing key field"
    [ -n "$WIN_IP" ] || die "malformed pairing descriptor: missing address field"
    is_wg_key "$WIN_PUB" || die "invalid WireGuard public key in pairing descriptor"
    is_tunnel_ip "$WIN_IP" || die "windows tunnel IP outside ${TUNNEL_SUBNET_PREFIX}0/24: $WIN_IP"
    [ "$WIN_IP" != "$(setting mac_ip "$DEFAULT_MAC_IP")" ] || die "the paired peer claims this Mac's tunnel address"
}

# ── settings ──────────────────────────────────────────────────────────────────────────────────
setting() {   # <key> [<default>]
    if [ -f "$SETTINGS" ]; then
        local v
        v="$(sed -n "s/^$1=//p" "$SETTINGS" | tail -n1)"
        [ -n "$v" ] && { printf '%s' "$v"; return 0; }
    fi
    printf '%s' "${2:-}"
}

save_settings() {   # endpoint port mac_ip win_ip peer_pub
    umask 077
    mkdir -p "$STATE_DIR"
    {
        printf 'endpoint=%s\n' "$1"
        printf 'listen_port=%s\n' "$2"
        printf 'mac_ip=%s\n' "$3"
        printf 'win_ip=%s\n' "$4"
        printf 'peer_public_key=%s\n' "$5"
    } >"${SETTINGS}.tmp"
    chmod 600 "${SETTINGS}.tmp"
    mv -f "${SETTINGS}.tmp" "$SETTINGS"
}

# ── identity ──────────────────────────────────────────────────────────────────────────────────
ensure_identity() {
    umask 077
    mkdir -p "$STATE_DIR"
    chown root:wheel "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    if [ -s "$PRIV_KEY" ] && [ -s "$PUB_KEY" ]; then
        is_wg_key "$(cat "$PRIV_KEY")" || die "stored private key is corrupt (uninstall --reset-identity to start over)"
        info "identity: existing key preserved"
        return
    fi
    [ ! -e "$PRIV_KEY" ] && [ ! -e "$PUB_KEY" ] || die "identity is half-written — run 'uninstall --reset-identity' first"
    "$HELPER" genkey >"${PRIV_KEY}.tmp"
    chmod 600 "${PRIV_KEY}.tmp"
    mv -f "${PRIV_KEY}.tmp" "$PRIV_KEY"
    "$HELPER" pubkey <"$PRIV_KEY" >"$PUB_KEY"
    chmod 644 "$PUB_KEY"
    chown root:wheel "$PRIV_KEY" "$PUB_KEY"
    info "identity: new keypair generated (private key never leaves this Mac)"
}

# ── configuration ─────────────────────────────────────────────────────────────────────────────
write_conf() {   # rewrites $CONF from the stored identity + settings; only when the bytes differ
    local peer_pub peer_ip staged_dir staged
    peer_pub="$(setting peer_public_key)"
    peer_ip="$(setting win_ip "$DEFAULT_WIN_IP")"
    staged_dir="$(mktemp -d)"
    staged="${staged_dir}/${TUNNEL_NAME}.conf"
    if [ -n "$peer_pub" ]; then
        render_conf "$(cat "$PRIV_KEY")" "$(setting mac_ip "$DEFAULT_MAC_IP")" "$(setting listen_port "$DEFAULT_LISTEN_PORT")" "$peer_pub" "$peer_ip" >"$staged"
    else
        render_conf "$(cat "$PRIV_KEY")" "$(setting mac_ip "$DEFAULT_MAC_IP")" "$(setting listen_port "$DEFAULT_LISTEN_PORT")" >"$staged"
    fi
    chmod 600 "$staged"
    # Validate before anything persistent changes: the helper parses the stanzas itself and fails
    # closed on anything that would widen the tunnel.
    local verdict
    if ! verdict="$("$HELPER" check "$staged" 2>&1 >/dev/null)"; then
        rm -rf "$staged_dir"
        die "generated WireGuard configuration failed validation: ${verdict:-no output from the helper}"
    fi
    if [ -f "$CONF" ] && cmp -s "$staged" "$CONF"; then
        rm -rf "$staged_dir"
        return 1
    fi
    mv -f "$staged" "$CONF"
    rmdir "$staged_dir" 2>/dev/null || true
    chown root:wheel "$CONF"
    return 0
}

# ── firewall (mandatory) ──────────────────────────────────────────────────────────────────────
install_pf() {
    local mac win port staged anchor_tmp backup
    mac="$(setting mac_ip "$DEFAULT_MAC_IP")"
    win="$(setting win_ip "$DEFAULT_WIN_IP")"
    port="$(setting listen_port "$DEFAULT_LISTEN_PORT")"

    anchor_tmp="$(mktemp)"
    render_pf "$mac" "$win" "$port" >"$anchor_tmp"
    pfctl -n -f "$anchor_tmp" >/dev/null 2>&1 || die "generated PF anchor failed syntax validation — no firewall change was made"
    mkdir -p /etc/pf.anchors
    if ! cmp -s "$anchor_tmp" "$PF_ANCHOR"; then
        install -m 644 -o root -g wheel "$anchor_tmp" "$PF_ANCHOR"
    fi
    rm -f "$anchor_tmp"

    # `pair` re-runs this after `init`. When /etc/pf.conf already loads our anchor there is nothing
    # to edit, so skip the backup and rewrite entirely and just reload — otherwise every pairing
    # leaves another identical copy in the backup directory.
    if grep -Fq "$PF_LOAD_LINE" "$PF_CONF"; then
        pfctl -E -f "$PF_CONF" >/dev/null 2>&1 ||
            die "activating PF failed — ${PF_CONF} was not modified; Screen Sharing isolation is NOT active"
        info "firewall: Screen Sharing (tcp ${SCSHR_TCP_PORTS}, udp ${SCSHR_UDP_PORTS}) reachable only from ${win}; udp/${port} open for WireGuard"
        return 0
    fi

    staged="$(mktemp)"
    cp "$PF_CONF" "$staged"
    # Smallest possible edit: two lines appended to the filter section.
    {
        printf '\n# scshr application tunnel isolation (added by scshr-macos-tunnel.sh)\n'
        printf '%s\n' "$PF_ANCHOR_LINE"
        printf '%s\n' "$PF_LOAD_LINE"
    } >>"$staged"
    if ! pfctl -n -f "$staged" >/dev/null 2>&1; then
        rm -f "$staged"
        die "PF configuration failed syntax validation — /etc/pf.conf was left untouched"
    fi

    mkdir -p "$PF_BACKUP_DIR"
    chmod 700 "$PF_BACKUP_DIR"
    backup="${PF_BACKUP_DIR}/pf.conf.$(date +%Y%m%d%H%M%S)"
    cp "$PF_CONF" "$backup"
    install -m 644 -o root -g wheel "$staged" "$PF_CONF"
    rm -f "$staged"

    if ! pfctl -E -f "$PF_CONF" >/dev/null 2>&1; then
        install -m 644 -o root -g wheel "$backup" "$PF_CONF"
        pfctl -f "$PF_CONF" >/dev/null 2>&1 || true
        die "activating PF failed — /etc/pf.conf was restored from ${backup}; Screen Sharing isolation is NOT installed"
    fi
    info "firewall: Screen Sharing (tcp ${SCSHR_TCP_PORTS}, udp ${SCSHR_UDP_PORTS}) reachable only from ${win}; udp/${port} open for WireGuard"
}

remove_pf() {
    if [ -f "$PF_CONF" ] && grep -Fq "$PF_LOAD_LINE" "$PF_CONF"; then
        local staged
        staged="$(mktemp)"
        grep -Fv "$PF_ANCHOR_LINE" "$PF_CONF" | grep -Fv "$PF_LOAD_LINE" |
            grep -Fv '# scshr application tunnel isolation (added by scshr-macos-tunnel.sh)' >"$staged"
        if pfctl -n -f "$staged" >/dev/null 2>&1; then
            install -m 644 -o root -g wheel "$staged" "$PF_CONF"
            pfctl -f "$PF_CONF" >/dev/null 2>&1 || true
            info "removed the scshr anchor from ${PF_CONF}"
        else
            info "WARNING: could not remove the scshr anchor cleanly; ${PF_CONF} left as is"
        fi
        rm -f "$staged"
    fi
    rm -f "$PF_ANCHOR"
    # PF itself is left enabled/disabled exactly as it was; other anchors are never touched.
}

# ── persistence ───────────────────────────────────────────────────────────────────────────────
install_helper() {
    local arch bundled
    arch="$(helper_arch)" || die "unsupported CPU architecture: $(uname -m)"
    bundled="${SCRIPT_DIR}/scshr-tunnel-darwin-${arch}"
    mkdir -p "$(dirname "$INSTALLED_HELPER")"
    if [ -x "$bundled" ]; then
        install -m 755 -o root -g wheel "$bundled" "$INSTALLED_HELPER"
    elif [ ! -x "$INSTALLED_HELPER" ]; then
        die "no scshr tunnel helper for ${arch} next to this script and none installed at ${INSTALLED_HELPER}"
    fi
    alf_allow_helper
}

install_launchd() {
    mkdir -p "$(dirname "$INSTALLED_SCRIPT")"
    install -m 755 -o root -g wheel "$0" "$INSTALLED_SCRIPT"
    render_plist "$INSTALLED_SCRIPT" >"${LAUNCHD_PLIST}.tmp"
    install -m 644 -o root -g wheel "${LAUNCHD_PLIST}.tmp" "$LAUNCHD_PLIST"
    rm -f "${LAUNCHD_PLIST}.tmp"
}

# Unloading returns as soon as launchd has signalled the job, but the old helper still holds the
# UAPI socket and udp/<listen-port> for a moment. Starting the replacement before it is gone makes
# the new process exit with "unix socket in use" or EADDRINUSE, and KeepAlive then sits out its
# 10 s throttle — so wait until nothing answers on the socket before loading again.
daemon_unload() {
    launchctl unload "$LAUNCHD_PLIST" >/dev/null 2>&1 || true
    local i=0
    while [ "$i" -lt 15 ]; do
        tunnel_is_up || break
        sleep 1
        i=$((i+1))
    done
    # A helper killed outright leaves both behind; the socket is unlinked on the next open, but a
    # stale interface name would make `status` report an interface that no longer exists.
    if ! tunnel_is_up; then rm -f "$UAPI_SOCKET" "$UTUN_NAME_FILE"; fi
}
daemon_load() {
    [ -f "$LAUNCHD_PLIST" ] || die "the scshr LaunchDaemon is not installed — run 'init' first"
    # Already-loaded is not an error: launchctl load is how this stays idempotent.
    launchctl load -w "$LAUNCHD_PLIST" >/dev/null 2>&1 || true
}

# ── lifecycle ─────────────────────────────────────────────────────────────────────────────────
tunnel_is_up() { [ -n "$HELPER" ] && "$HELPER" status >/dev/null 2>&1; }

# 30s, not 10: a helper that lost a race with its predecessor is restarted by KeepAlive only after
# launchd's 10 s throttle, and that retry must still be inside the window.
wait_up() {
    local i=0
    while [ "$i" -lt 30 ]; do
        if tunnel_is_up; then return 0; fi
        sleep 1
        i=$((i+1))
    done
    tunnel_is_up
}

# Executed by launchd. PF first and fail closed: if isolation cannot be activated the tunnel must
# not start, and KeepAlive will retry rather than leave Screen Sharing exposed.
cmd_run() {
    need_root
    require_helper
    [ -f "$CONF" ] || die "not initialised — run 'init' first"
    pfctl -E -f "$PF_CONF" >/dev/null 2>&1 ||
        die "could not activate PF — refusing to start the tunnel with Screen Sharing exposed"
    exec "$HELPER" run "$CONF"
}

cmd_up() {
    need_root
    require_helper
    [ -f "$CONF" ] || die "not initialised — run 'init' first"
    daemon_load
    wait_up || die "the tunnel did not come up within 30s — see ${TUNNEL_LOG}"
    info "tunnel up: $(setting mac_ip "$DEFAULT_MAC_IP")/32 listening on udp/$(setting listen_port "$DEFAULT_LISTEN_PORT")"
}

cmd_down() {
    need_root
    find_helper || true
    daemon_unload
    # PF rules stay in place: taking the tunnel down must not re-expose Screen Sharing.
    info "tunnel down (Screen Sharing isolation remains active)"
}

# ── environment report (consumed by the Windows wizard) ───────────────────────────────────────
screen_sharing_state() {
    if launchctl print "system/com.apple.screensharing" >/dev/null 2>&1; then
        printf 'enabled'
    elif [ -f "$SCREEN_SHARING_PLIST" ]; then
        printf 'disabled'
    else
        printf 'unknown'
    fi
}

cmd_preflight() {
    local helper_state="missing"
    if find_helper; then helper_state="ok"; fi
    printf 'macos_version=%s\n' "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
    printf 'arch=%s\n' "$(uname -m)"
    printf 'helper=%s\n' "$helper_state"
    printf 'pf_conf=%s\n' "$([ -f "$PF_CONF" ] && echo present || echo missing)"
    printf 'screen_sharing=%s\n' "$(screen_sharing_state)"
    # Only reached when sudo already worked, so this is a constant by construction.
    printf 'sudo=ok\n'
    printf 'firewall=%s\n' "$(alf_state)"
    [ "$helper_state" = "ok" ] || die "no scshr tunnel helper for this Mac ($(uname -m)) — upload the matching helper next to this script"
}

cmd_enable_screen_sharing() {
    need_root
    [ -f "$SCREEN_SHARING_PLIST" ] || die "${SCREEN_SHARING_PLIST} not found — this macOS does not ship Screen Sharing where scshr expects it"
    launchctl load -w "$SCREEN_SHARING_PLIST" >/dev/null 2>&1 || true
    local state
    state="$(screen_sharing_state)"
    printf 'screen_sharing=%s\n' "$state"
    [ "$state" = "enabled" ] ||
        die "Screen Sharing is still off — on the Mac, turn on System Settings > General > Sharing > Screen Sharing"
}

cmd_init() {
    local endpoint="" port="$DEFAULT_LISTEN_PORT" mac_ip="$DEFAULT_MAC_IP" win_ip="$DEFAULT_WIN_IP"
    while [ $# -gt 0 ]; do
        case "$1" in
            --endpoint) endpoint="${2:-}"; shift 2 ;;
            --listen-port) port="${2:-}"; shift 2 ;;
            --mac-ip) mac_ip="${2:-}"; shift 2 ;;
            --win-ip) win_ip="${2:-}"; shift 2 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
    need_root
    require_helper
    command -v pfctl >/dev/null 2>&1 || die "pfctl not found — this script requires macOS packet filter"
    [ -f "$PF_CONF" ] || die "${PF_CONF} not found — refusing to create one from scratch"
    [ -n "$endpoint" ] || die "--endpoint is required: the public hostname or IP at which this Mac's WireGuard port is reachable"
    is_endpoint_host "$endpoint" || die "invalid --endpoint: $endpoint"
    is_port "$port" || die "invalid --listen-port: $port"
    is_tunnel_ip "$mac_ip" || die "invalid --mac-ip (must be inside ${TUNNEL_SUBNET_PREFIX}0/24): $mac_ip"
    is_tunnel_ip "$win_ip" || die "invalid --win-ip (must be inside ${TUNNEL_SUBNET_PREFIX}0/24): $win_ip"
    [ "$mac_ip" != "$win_ip" ] || die "--mac-ip and --win-ip must differ"

    ensure_identity
    save_settings "$endpoint" "$port" "$mac_ip" "$win_ip" "$(setting peer_public_key)"
    if write_conf; then info "configuration written to ${CONF}"; else info "configuration already current"; fi
    install_pf
    install_helper
    install_launchd
    daemon_unload
    daemon_load
    wait_up || die "the tunnel did not come up within 30s — see ${TUNNEL_LOG}"

    if [ "$(sysctl -n net.inet.ip.forwarding 2>/dev/null || echo 0)" != "0" ]; then
        info "NOTE: IP forwarding is enabled on this Mac by something else — scshr did not enable it and does not need it"
    fi

    printf '\n'
    info "macOS tunnel ready."
    printf 'Next:\n'
    printf '  1. On Windows:  .\\scshr.exe init      (paste the code below)\n'
    printf '  2. Back here :  sudo %s pair '"'"'SCCL1:<code Windows printed>'"'"'\n' "$0"
    # Advice goes to stderr so the pairing code is the last line on stdout: the Windows wizard
    # extracts the code from stdout and must not have to skip trailing prose.
    printf 'If this Mac is behind NAT, forward udp/%s to it; nothing else needs to be reachable.\n' "$port" >&2
    printf 'Pairing code for Windows:\n'
    render_server_code "$(cat "$PUB_KEY")" "$endpoint" "$port" "$mac_ip" "$win_ip"
}

cmd_pair() {
    local code="${1:-}"
    [ -n "$code" ] || die "usage: pair 'SCCL1:<windows-code>'"
    need_root
    require_helper
    [ -s "$PRIV_KEY" ] || die "not initialised — run 'init' first"
    decode_client_code "$code"
    [ "$WIN_IP" = "$(setting win_ip "$DEFAULT_WIN_IP")" ] ||
        die "the Windows peer claims ${WIN_IP} but this Mac was initialised for $(setting win_ip "$DEFAULT_WIN_IP")"
    save_settings "$(setting endpoint)" "$(setting listen_port "$DEFAULT_LISTEN_PORT")" \
                  "$(setting mac_ip "$DEFAULT_MAC_IP")" "$WIN_IP" "$WIN_PUB"
    if write_conf; then
        daemon_unload
        daemon_load
        wait_up || die "the tunnel did not come back up within 30s — see ${TUNNEL_LOG}"
        info "paired with Windows peer $(printf '%s' "$WIN_PUB" | cut -c1-8)… at ${WIN_IP}/32"
    else
        info "already paired with this peer"
    fi
    install_pf
}

cmd_status() {
    need_root
    require_helper
    printf 'scshr macOS tunnel\n'
    printf '  configuration   : %s\n' "$([ -f "$CONF" ] && echo present || echo missing)"
    printf '  local address   : %s/32\n' "$(setting mac_ip "$DEFAULT_MAC_IP")"
    printf '  peer address    : %s/32\n' "$(setting win_ip "$DEFAULT_WIN_IP")"
    printf '  public endpoint : %s:%s\n' "$(setting endpoint '(unset)')" "$(setting listen_port "$DEFAULT_LISTEN_PORT")"
    printf '  public key      : %s\n' "$([ -f "$PUB_KEY" ] && cat "$PUB_KEY" || echo '(none)')"
    if tunnel_is_up; then
        printf '  state           : up\n'
        "$HELPER" status | sed 's/^/    /'
    else
        printf '  state           : down\n'
    fi
    printf '  ip forwarding   : %s (scshr never enables it)\n' "$(sysctl -n net.inet.ip.forwarding 2>/dev/null || echo unknown)"
    printf '  pf              : %s\n' "$(pfctl -s info 2>/dev/null | sed -n '1s/^Status: //p' || echo unknown)"
    printf '  isolation rules :\n'
    pfctl -a "$TUNNEL_NAME" -s rules 2>/dev/null | sed 's/^/    /' || printf '    (anchor not loaded)\n'
    printf '  screen sharing  : %s\n' "$(screen_sharing_state)"
    printf '  launchd         : %s\n' "$([ -f "$LAUNCHD_PLIST" ] && echo installed || echo 'not installed')"
    # Private key material is never printed.
}

cmd_uninstall() {
    local reset=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --reset-identity) reset=1; shift ;;
            *) die "unknown argument: $1" ;;
        esac
    done
    need_root
    find_helper || true
    if [ -f "$LAUNCHD_PLIST" ]; then
        daemon_unload
        rm -f "$LAUNCHD_PLIST"
        info "removed ${LAUNCHD_PLIST}"
    fi
    alf_remove_helper
    rm -f "$INSTALLED_SCRIPT" "$INSTALLED_HELPER"
    remove_pf
    rm -f "$CONF" "$SETTINGS"
    if [ "$reset" = "1" ]; then
        rm -f "$PRIV_KEY" "$PUB_KEY"
        info "identity keys removed"
    else
        info "identity keys preserved (pass --reset-identity to discard them)"
    fi
    rmdir "$STATE_DIR" 2>/dev/null || true
    info "removed scshr-owned state only; other WireGuard tunnels, PF anchors and software were not touched"
}

usage() {
    cat <<USAGE
scshr macOS tunnel

  sudo $0 preflight
  sudo $0 init --endpoint HOST [--listen-port ${DEFAULT_LISTEN_PORT}] [--mac-ip ${DEFAULT_MAC_IP}] [--win-ip ${DEFAULT_WIN_IP}]
  sudo $0 pair 'SCCL1:<windows-code>'
  sudo $0 up | down | status | run
  sudo $0 enable-screen-sharing
  sudo $0 uninstall [--reset-identity]

Test helpers (no root, no side effects):
  $0 render-conf <private-key> <mac-ip> <port> [<peer-public-key> <peer-ip>]
  $0 render-pf <mac-ip> <win-ip> <listen-port>
  $0 render-plist <installed-script>
  $0 render-preflight-keys
  $0 render-server-code <public-key> <endpoint> <port> <mac-ip> <win-ip>
  $0 render-client-code <public-key> <win-ip>
  $0 decode-client-code <SCCL1:...>
USAGE
}

case "${1:-}" in
    preflight) shift; cmd_preflight "$@" ;;
    init) shift; cmd_init "$@" ;;
    pair) shift; cmd_pair "$@" ;;
    run) shift; cmd_run "$@" ;;
    up) shift; cmd_up "$@" ;;
    down) shift; cmd_down "$@" ;;
    status) shift; cmd_status "$@" ;;
    enable-screen-sharing) shift; cmd_enable_screen_sharing "$@" ;;
    uninstall) shift; cmd_uninstall "$@" ;;
    render-conf) shift; render_conf "$@" ;;
    render-pf) shift; render_pf "$@" ;;
    render-plist) shift; render_plist "${1:-$INSTALLED_SCRIPT}" ;;
    render-preflight-keys) shift; render_preflight_keys ;;
    render-server-code) shift; render_server_code "$@" ;;
    render-client-code) shift; render_client_code "$@" ;;
    decode-client-code) shift; decode_client_code "${1:-}"; printf '%s %s\n' "$WIN_PUB" "$WIN_IP" ;;
    -h|--help|help|"") usage ;;
    *) usage; exit 2 ;;
esac
