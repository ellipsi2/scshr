package main

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestParseSub(t *testing.T) {
	if a, bye, err := parseSub([]byte("SCAU1 sub alice\n")); err != nil || bye || a != "alice" {
		t.Fatalf("sub: %q %v %v", a, bye, err)
	}
	if _, bye, err := parseSub([]byte("SCAU1 bye")); err != nil || !bye {
		t.Fatalf("bye: %v %v", bye, err)
	}
	for _, bad := range []string{"", "SCAU1 sub ", "SCAU1 sub a b", "SCAU1 sub ../x", "SCAU1 sub " + string(make([]byte, 65)), "SCAUx"} {
		if _, _, err := parseSub([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

type fakeAgent struct {
	a    *relayAgent
	cmds []byte
}

func newFakeAgent(uid uint32) *fakeAgent {
	f := &fakeAgent{}
	f.a = &relayAgent{uid: uid, cmd: func(c byte) { f.cmds = append(f.cmds, c) }}
	return f
}

func TestRelayRoutesOnlyTheSubscribedAccount(t *testing.T) {
	var sent []string
	r := newRelay(
		func(account string) (uint32, error) {
			if account == "remote" {
				return 502, nil
			}
			if account == "console" {
				return 501, nil
			}
			return 0, fmt.Errorf("no such user")
		},
		func(to *net.UDPAddr, b []byte) { sent = append(sent, to.String()+":"+string(b)) },
		func(string, ...any) {},
	)
	console, remote := newFakeAgent(501), newFakeAgent(502)
	r.addAgent(console.a)
	r.addAgent(remote.a)
	client := &net.UDPAddr{IP: net.IPv4(10, 77, 77, 2), Port: 40000}
	t0 := time.Unix(1000, 0)

	// Unknown account: a status reply, nobody started.
	r.onDatagram(client, []byte("SCAU1 sub nobody"), t0)
	if len(sent) != 1 || sent[0] != "10.77.77.2:40000:SCAU1 status unknown-account nobody" {
		t.Fatalf("unknown account: %v", sent)
	}
	if len(console.cmds)+len(remote.cmds) != 0 {
		t.Fatalf("agent started for an unknown account")
	}
	sent = nil

	// Subscribing as the remote account starts only that agent, and only its audio is forwarded.
	r.onDatagram(client, []byte("SCAU1 sub remote"), t0)
	if string(remote.cmds) != "s" || len(console.cmds) != 0 {
		t.Fatalf("start commands: remote=%q console=%q", remote.cmds, console.cmds)
	}
	r.onAgentFrame(console.a, frameAudio, []byte("C"))
	r.onAgentFrame(remote.a, frameAudio, []byte("R"))
	if len(sent) != 1 || sent[0] != "10.77.77.2:40000:R" {
		t.Fatalf("forwarded: %v", sent)
	}
	// Renewing does not restart.
	r.onDatagram(client, []byte("SCAU1 sub remote"), t0.Add(time.Second))
	if string(remote.cmds) != "s" {
		t.Fatalf("renew restarted: %q", remote.cmds)
	}

	// Switching accounts stops the old agent and starts the new one.
	r.onDatagram(client, []byte("SCAU1 sub console"), t0.Add(2*time.Second))
	if string(remote.cmds) != "sx" || string(console.cmds) != "s" {
		t.Fatalf("switch: remote=%q console=%q", remote.cmds, console.cmds)
	}

	// Timeout stops everything; a later subscribe starts again.
	r.tick(t0.Add(2*time.Second + audioSubTimeout + time.Millisecond))
	if string(console.cmds) != "sx" || r.client != nil {
		t.Fatalf("timeout: console=%q client=%v", console.cmds, r.client)
	}
	r.onDatagram(client, []byte("SCAU1 sub console"), t0.Add(10*time.Second))
	if string(console.cmds) != "sxs" {
		t.Fatalf("resubscribe: %q", console.cmds)
	}

	// The agent going away (KeepAlive restart) and coming back is picked up on the next renewal.
	r.removeAgent(console.a)
	console2 := newFakeAgent(501)
	r.addAgent(console2.a)
	r.onDatagram(client, []byte("SCAU1 sub console"), t0.Add(11*time.Second))
	if string(console2.cmds) != "s" {
		t.Fatalf("reconnected agent not started: %q", console2.cmds)
	}

	// bye stops the agent immediately.
	r.onDatagram(client, []byte("SCAU1 bye"), t0.Add(12*time.Second))
	if string(console2.cmds) != "sx" || r.client != nil {
		t.Fatalf("bye: %q %v", console2.cmds, r.client)
	}
}

func TestAudioPacketFraming(t *testing.T) {
	pcm := make([]float32, 2*(audioMaxFrames+10))
	for i := range pcm {
		pcm[i] = 0.5
	}
	var pkts [][]byte
	seq := uint16(65535)
	packetize(pcm, 2, 44100, &seq, func(b []byte) { pkts = append(pkts, b) })
	if len(pkts) != 2 {
		t.Fatalf("packets: %d", len(pkts))
	}
	if n := len(pkts[0]); n != audioHeaderLen+audioMaxFrames*4 {
		t.Fatalf("first packet %d bytes", n)
	}
	h := pkts[0]
	if string(h[:4]) != audioMagic || h[4] != 1 || h[5] != 2 {
		t.Fatalf("header %v", h[:6])
	}
	if got := uint16(h[6]) | uint16(h[7])<<8; got != 65535 {
		t.Fatalf("seq %d", got)
	}
	if got := uint16(pkts[1][6]) | uint16(pkts[1][7])<<8; got != 0 {
		t.Fatalf("seq wrap %d", got)
	}
	if rate := uint32(h[8]) | uint32(h[9])<<8 | uint32(h[10])<<16 | uint32(h[11])<<24; rate != 44100 {
		t.Fatalf("rate %d", rate)
	}
	if frames := uint16(pkts[1][12]) | uint16(pkts[1][13])<<8; frames != 10 {
		t.Fatalf("second packet frames %d", frames)
	}
	if s := int16(uint16(h[16]) | uint16(h[17])<<8); s != 16383 {
		t.Fatalf("sample %d", s)
	}
	// Silence is not sent.
	pkts = nil
	packetize(make([]float32, 200), 2, 48000, &seq, func(b []byte) { pkts = append(pkts, b) })
	if len(pkts) != 0 {
		t.Fatalf("silence sent: %d packets", len(pkts))
	}
	// Mono is duplicated into both channels; clipping saturates.
	pkts = nil
	packetize([]float32{2.0, -2.0}, 1, 48000, &seq, func(b []byte) { pkts = append(pkts, b) })
	if len(pkts) != 1 || len(pkts[0]) != audioHeaderLen+2*4 {
		t.Fatalf("mono: %v", pkts)
	}
	p := pkts[0]
	l0 := int16(uint16(p[16]) | uint16(p[17])<<8)
	r0 := int16(uint16(p[18]) | uint16(p[19])<<8)
	l1 := int16(uint16(p[20]) | uint16(p[21])<<8)
	if l0 != 32767 || r0 != 32767 || l1 != -32768 {
		t.Fatalf("mono/clip: %d %d %d", l0, r0, l1)
	}
}
