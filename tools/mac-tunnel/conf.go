package main

// Parsing and fail-closed validation of the scshr WireGuard configuration, plus the UAPI text
// wireguard-go is configured with. Deliberately not a general wg-quick parser: this tunnel only
// ever describes one macOS peer and one Windows peer inside 10.77.77.0/24, so anything that could
// widen it (DNS, Table, MTU, PreUp/PostUp, Endpoint, extra peers, wider AllowedIPs) is an error
// rather than something to interpret.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The only subnet this tunnel is ever allowed to carry.
var tunnelSubnet = netip.MustParsePrefix("10.77.77.0/24")

type conf struct {
	PrivateKey string // canonical padded base64, 44 chars
	Address    netip.Addr
	ListenPort uint16

	HasPeer       bool
	PeerPublicKey string
	PeerAllowedIP netip.Addr
}

// decodeKey accepts only the canonical 44-character padded base64 spelling of a 32-byte key.
func decodeKey(s string) ([]byte, error) {
	if len(s) != 44 || !strings.HasSuffix(s, "=") {
		return nil, fmt.Errorf("not a 44-character base64 WireGuard key")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("not a valid base64 WireGuard key")
	}
	// Reject non-canonical spellings so a key has exactly one representation.
	if base64.StdEncoding.EncodeToString(raw) != s {
		return nil, fmt.Errorf("non-canonical base64 WireGuard key")
	}
	return raw, nil
}

// hostInTunnel accepts "a.b.c.d/32" whose address is a usable host inside 10.77.77.0/24.
func hostInTunnel(cidr string) (netip.Addr, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an address/prefix", cidr)
	}
	if !p.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("%q is not IPv4", cidr)
	}
	if p.Bits() != 32 {
		return netip.Addr{}, fmt.Errorf("%q is wider than /32", cidr)
	}
	a := p.Addr()
	if !tunnelSubnet.Contains(a) {
		return netip.Addr{}, fmt.Errorf("%q is outside %s", cidr, tunnelSubnet)
	}
	last := a.As4()[3]
	if last == 0 || last == 255 {
		return netip.Addr{}, fmt.Errorf("%q is the network or broadcast address", cidr)
	}
	return a, nil
}

var (
	interfaceKeys = map[string]bool{"privatekey": true, "address": true, "listenport": true}
	peerKeys      = map[string]bool{"publickey": true, "allowedips": true}
)

func parseConf(text string) (*conf, error) {
	c := &conf{}
	section := ""
	seenInterface := 0
	seenPeer := 0
	seen := map[string]bool{}

	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		at := func(f string, a ...any) error {
			return fmt.Errorf("line %d: %s", n+1, fmt.Sprintf(f, a...))
		}
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[Interface]":
				section, seenInterface = "interface", seenInterface+1
			case "[Peer]":
				section, seenPeer = "peer", seenPeer+1
			default:
				return nil, at("unknown section %q", line)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, at("not a key = value line: %q", line)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if section == "" {
			return nil, at("%q appears before any section", key)
		}
		dupKey := section + "." + key + "." + strconv.Itoa(seenPeer)
		if seen[dupKey] {
			return nil, at("duplicate key %q", key)
		}
		seen[dupKey] = true

		switch section {
		case "interface":
			if !interfaceKeys[key] {
				return nil, at("key %q is not allowed in [Interface] (this tunnel must never widen)", key)
			}
			switch key {
			case "privatekey":
				if _, err := decodeKey(val); err != nil {
					return nil, at("PrivateKey: %v", err)
				}
				c.PrivateKey = val
			case "address":
				a, err := hostInTunnel(val)
				if err != nil {
					return nil, at("Address: %v", err)
				}
				c.Address = a
			case "listenport":
				p, err := strconv.Atoi(val)
				if err != nil || p < 1 || p > 65535 {
					return nil, at("ListenPort: %q is not a port in 1..65535", val)
				}
				c.ListenPort = uint16(p)
			}
		case "peer":
			if !peerKeys[key] {
				return nil, at("key %q is not allowed in [Peer] (this tunnel must never widen)", key)
			}
			switch key {
			case "publickey":
				if _, err := decodeKey(val); err != nil {
					return nil, at("PublicKey: %v", err)
				}
				c.PeerPublicKey = val
			case "allowedips":
				parts := strings.Split(val, ",")
				if len(parts) != 1 {
					return nil, at("AllowedIPs must list exactly one /32")
				}
				a, err := hostInTunnel(strings.TrimSpace(parts[0]))
				if err != nil {
					return nil, at("AllowedIPs: %v", err)
				}
				c.PeerAllowedIP = a
			}
		}
	}

	if seenInterface != 1 {
		return nil, fmt.Errorf("expected exactly one [Interface] section, found %d", seenInterface)
	}
	if seenPeer > 1 {
		return nil, fmt.Errorf("expected at most one [Peer] section, found %d", seenPeer)
	}
	if c.PrivateKey == "" {
		return nil, fmt.Errorf("[Interface] is missing PrivateKey")
	}
	if !c.Address.IsValid() {
		return nil, fmt.Errorf("[Interface] is missing Address")
	}
	if c.ListenPort == 0 {
		return nil, fmt.Errorf("[Interface] is missing ListenPort")
	}
	if seenPeer == 1 {
		if c.PeerPublicKey == "" {
			return nil, fmt.Errorf("[Peer] is missing PublicKey")
		}
		if !c.PeerAllowedIP.IsValid() {
			return nil, fmt.Errorf("[Peer] is missing AllowedIPs")
		}
		if c.PeerAllowedIP == c.Address {
			return nil, fmt.Errorf("[Peer] AllowedIPs is this interface's own address")
		}
		c.HasPeer = true
	}
	return c, nil
}

// uapi renders the wireguard-go IpcSet document for this configuration.
func (c *conf) uapi() (string, error) {
	priv, err := decodeKey(c.PrivateKey)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(priv))
	fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	b.WriteString("replace_peers=true\n")
	if c.HasPeer {
		pub, err := decodeKey(c.PeerPublicKey)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub))
		b.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&b, "allowed_ip=%s/32\n", c.PeerAllowedIP)
	}
	b.WriteString("\n")
	return b.String(), nil
}
