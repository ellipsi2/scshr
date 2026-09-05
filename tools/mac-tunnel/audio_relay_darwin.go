//go:build darwin

package main

// Socket plumbing for the audio relay (root, inside `scshr-tunnel run`).

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// lookupAccountUID resolves a macOS account name the way the login window sees it (Open Directory,
// not /etc/passwd, so `id -u` rather than os/user which is not cgo-backed in this static binary).
func lookupAccountUID(account string) (uint32, error) {
	out, err := exec.Command("/usr/bin/id", "-u", account).Output()
	if err != nil {
		return 0, fmt.Errorf("no such account %q", account)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			gerr = e
			return
		}
		uid = cred.Uid
	}); err != nil {
		return 0, err
	}
	return uid, gerr
}

// startAudioRelay listens on udp <addr>:5902 and the agent socket. Failures are reported, not fatal:
// the tunnel must keep running without session audio.
func startAudioRelay(addr netip.Addr) error {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: addr.AsSlice(), Port: audioRelayPort})
	if err != nil {
		return fmt.Errorf("udp/%d on %s: %w", audioRelayPort, addr, err)
	}
	os.Remove(audioAgentSocket)
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: audioAgentSocket, Net: "unix"})
	if err != nil {
		udp.Close()
		return fmt.Errorf("%s: %w", audioAgentSocket, err)
	}
	if err := os.Chmod(audioAgentSocket, 0o666); err != nil { // agents run as ordinary users
		ul.Close()
		udp.Close()
		return err
	}
	logf := func(format string, args ...any) { fmt.Printf("scshr-tunnel: "+format+"\n", args...) }
	r := newRelay(lookupAccountUID, func(to *net.UDPAddr, b []byte) { _, _ = udp.WriteToUDP(b, to) }, logf)

	go func() {
		for {
			c, err := ul.AcceptUnix()
			if err != nil {
				return
			}
			go serveAgent(r, c)
		}
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.onDatagram(from, buf[:n], time.Now())
		}
	}()
	go func() {
		for range time.Tick(time.Second) {
			r.tick(time.Now())
		}
	}()
	fmt.Printf("scshr-tunnel: session audio relay on udp/%d\n", audioRelayPort)
	return nil
}

func serveAgent(r *relay, c *net.UnixConn) {
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil {
		fmt.Printf("scshr-tunnel: audio agent rejected (no peer credentials: %v)\n", err)
		return
	}
	a := &relayAgent{uid: uid, cmd: func(b byte) { _ = c.SetWriteDeadline(time.Now().Add(time.Second)); _, _ = c.Write([]byte{b}) }}
	r.addAgent(a)
	defer r.removeAgent(a)
	hdr := make([]byte, 5)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		n := binary.LittleEndian.Uint32(hdr[1:])
		if n > 4096 {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
		r.onAgentFrame(a, hdr[0], payload)
	}
}
