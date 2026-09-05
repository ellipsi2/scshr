// Command scshr-tunnel is the self-contained macOS side of the scshr application tunnel.
//
// It replaces Homebrew's wireguard-tools (wg / wg-quick) so a stock Mac needs nothing installed:
// a single static binary that generates keys, validates the scshr configuration, runs the tunnel
// in userspace (wireguard-go) and reports its status.
//
//	scshr-tunnel genkey            → a new private key on stdout
//	scshr-tunnel pubkey            → the public key for the private key on stdin
//	scshr-tunnel check <conf>      → exit 0 if <conf> is a valid scshr tunnel configuration
//	scshr-tunnel run <conf>        → run the tunnel in the foreground (launchd supervises it)
//	scshr-tunnel status            → key=value status of the running tunnel
//	scshr-tunnel audio-agent       → per-user session audio agent (a LaunchAgent; see audio_relay.go)
//	scshr-tunnel audio-tap-test [s] → tap this account's audio for s seconds and report (diagnostics)
//
// Private key material is never printed except by genkey, which is the command that mints it.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	// The UAPI socket name is fixed so status can find the tunnel whatever utun number it got.
	uapiName    = "scshr"
	uapiSocket  = "/var/run/wireguard/scshr.sock"
	utunNameFil = "/var/run/scshr-tunnel.utun"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "scshr-tunnel: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: scshr-tunnel genkey|pubkey|check <conf>|run <conf>|status|audio-agent")
	}
	switch args[0] {
	case "audio-agent":
		return cmdAudioAgent()
	case "audio-tap-test":
		return cmdAudioTapTest(args[1:])
	case "genkey":
		return cmdGenkey()
	case "pubkey":
		return cmdPubkey()
	case "check":
		if len(args) != 2 {
			return fmt.Errorf("usage: scshr-tunnel check <conf>")
		}
		_, err := loadConf(args[1])
		return err
	case "run":
		if len(args) != 2 {
			return fmt.Errorf("usage: scshr-tunnel run <conf>")
		}
		c, err := loadConf(args[1])
		if err != nil {
			return err
		}
		return runTunnel(c)
	case "status":
		return cmdStatus()
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func loadConf(path string) (*conf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := parseConf(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return c, nil
}

// ── keys ──────────────────────────────────────────────────────────────────────────────────────

// clamp applies the Curve25519 private-key clamping wg genkey does.
func clamp(k []byte) {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

func cmdGenkey() error {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return err
	}
	clamp(k[:])
	fmt.Println(base64.StdEncoding.EncodeToString(k[:]))
	return nil
}

func publicKey(privB64 string) (string, error) {
	priv, err := decodeKey(privB64)
	if err != nil {
		return "", err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func cmdPubkey() error {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	pub, err := publicKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	fmt.Println(pub)
	return nil
}

func publicKeyFromHex(privHex string) string {
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != 32 {
		return ""
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// ── status ────────────────────────────────────────────────────────────────────────────────────

// statusFields turns a UAPI get=1 reply into the key=value lines the shell script prints.
func statusFields(reply string) []string {
	var pub, listenPort, peerPub, endpoint, keepalive, rx, tx string
	var hsSec string
	var allowed []string
	for _, line := range strings.Split(reply, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "private_key":
			pub = publicKeyFromHex(v)
		case "listen_port":
			listenPort = v
		case "public_key":
			if raw, err := hex.DecodeString(v); err == nil && len(raw) == 32 {
				peerPub = base64.StdEncoding.EncodeToString(raw)
			}
		case "endpoint":
			endpoint = v
		case "allowed_ip":
			allowed = append(allowed, v)
		case "last_handshake_time_sec":
			hsSec = v
		case "rx_bytes":
			rx = v
		case "tx_bytes":
			tx = v
		case "persistent_keepalive_interval":
			keepalive = v
		}
	}
	if hsSec == "" {
		hsSec = "0"
	}
	utun := ""
	if b, err := os.ReadFile(utunNameFil); err == nil {
		utun = strings.TrimSpace(string(b))
	}
	return []string{
		"interface=" + utun,
		"public_key=" + pub,
		"listen_port=" + listenPort,
		"peer_public_key=" + peerPub,
		"endpoint=" + endpoint,
		"allowed_ips=" + strings.Join(allowed, ","),
		"last_handshake_unix=" + hsSec,
		"rx_bytes=" + zeroDefault(rx),
		"tx_bytes=" + zeroDefault(tx),
		"persistent_keepalive=" + zeroDefault(keepalive),
	}
}

func zeroDefault(s string) string {
	if s == "" {
		return "0"
	}
	if _, err := strconv.Atoi(s); err != nil {
		return "0"
	}
	return s
}

func cmdStatus() error {
	c, err := net.Dial("unix", uapiSocket)
	if err != nil {
		return fmt.Errorf("tunnel is not running (%s: %v)", uapiSocket, err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "get=1\n\n"); err != nil {
		return fmt.Errorf("tunnel did not accept the status request: %v", err)
	}
	var b strings.Builder
	s := bufio.NewScanner(c)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			break
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("reading tunnel status failed: %v", err)
	}
	if b.Len() == 0 {
		return fmt.Errorf("tunnel returned an empty status")
	}
	for _, line := range statusFields(b.String()) {
		fmt.Println(line)
	}
	return nil
}
