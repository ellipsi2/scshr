package main

// Session audio relay (portable core; the sockets live in audio_relay_darwin.go).
//
// Apple's High Performance screen sharing sends the whole Mac's sound to the viewer and mutes the
// Mac's own speakers, for every logged-in user at once. scshr instead turns Apple's audio stream off
// and captures only the remote user's session: a per-user audio agent (`scshr-tunnel audio-agent`, a
// LaunchAgent in every GUI login session) taps the processes running as that account through a
// CoreAudio process tap, muted locally, and hands the PCM to this relay inside the root tunnel daemon.
// The relay owns UDP <mac-ip>:5902 — reachable only across the tunnel, PF-guarded — and forwards the
// packets of the agent whose uid matches the account the Windows client logged in with.
//
// Wire protocol (all over the tunnel, so already encrypted and peer-authenticated):
//   client → relay   "SCAU1 sub <account>"  once a second while sound is wanted; "SCAU1 bye" on exit
//   relay  → client  "SCAU1 status <text>"  why there is no sound yet (unknown account, no agent …)
//   relay  → client  audio packets: "SCAU" ver=1 channels=2 seq:u16le rate:u32le frames:u16le 0:u16le
//                    followed by frames×2 int16le samples (≤ audioMaxFrames, so one datagram fits the
//                    tunnel MTU). Silent buffers are not sent at all.
//   agent  → relay   unix stream frames: type:u8 len:u32le payload; type 1 = an audio packet exactly
//                    as sent to the client, type 2 = a status text for the client and the log
//   relay  → agent   single bytes: 's' start tapping, 'x' stop

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	audioRelayPort   = 5902
	audioAgentSocket = "/var/run/scshr-audio.sock"
	audioSubTimeout  = 3 * time.Second
	audioMagic       = "SCAU"
	audioHeaderLen   = 16
	audioMaxFrames   = 340 // 16 + 340*4 = 1376 B < 1420 B tunnel MTU − 28 B IP/UDP
	audioMaxAccount  = 64

	frameAudio  = 1
	frameStatus = 2
	cmdStart    = 's'
	cmdStop     = 'x'
)

// relayAgent is one connected audio agent (one per logged-in macOS account).
type relayAgent struct {
	uid     uint32
	cmd     func(byte)
	started bool
}

type relay struct {
	mu        sync.Mutex
	agents    map[*relayAgent]struct{}
	lookupUID func(account string) (uint32, error)
	send      func(to *net.UDPAddr, b []byte)
	logf      func(format string, args ...any)

	uidCache  map[string]uint32
	client    *net.UDPAddr
	clientUID uint32
	lastSub   time.Time
	active    *relayAgent
}

func newRelay(lookupUID func(string) (uint32, error), send func(*net.UDPAddr, []byte), logf func(string, ...any)) *relay {
	return &relay{
		agents:    map[*relayAgent]struct{}{},
		lookupUID: lookupUID,
		send:      send,
		logf:      logf,
		uidCache:  map[string]uint32{},
	}
}

func (r *relay) addAgent(a *relayAgent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[a] = struct{}{}
	r.logf("audio agent connected (uid %d)", a.uid)
}

func (r *relay) removeAgent(a *relayAgent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, a)
	if r.active == a {
		r.active = nil
	}
	r.logf("audio agent disconnected (uid %d)", a.uid)
}

// onAgentFrame forwards an agent's audio to the subscriber (only the agent the subscriber asked for).
func (r *relay) onAgentFrame(a *relayAgent, kind byte, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch kind {
	case frameAudio:
		if r.active == a && r.client != nil {
			r.send(r.client, payload)
		}
	case frameStatus:
		text := strings.TrimSpace(string(payload))
		r.logf("audio agent (uid %d): %s", a.uid, text)
		if r.active == a && r.client != nil {
			r.status(text)
		}
	}
}

func (r *relay) status(text string) { r.send(r.client, []byte("SCAU1 status "+text)) }

func (r *relay) stopActiveLocked() {
	if r.active != nil && r.active.started {
		r.active.cmd(cmdStop)
		r.active.started = false
	}
	r.active = nil
}

// parseSub returns the account of a "SCAU1 sub <account>" datagram, "" for "SCAU1 bye", or an error.
func parseSub(b []byte) (account string, bye bool, err error) {
	s := strings.TrimRight(string(b), "\r\n")
	switch {
	case s == "SCAU1 bye":
		return "", true, nil
	case strings.HasPrefix(s, "SCAU1 sub "):
		account = strings.TrimPrefix(s, "SCAU1 sub ")
		if account == "" || len(account) > audioMaxAccount || strings.ContainsAny(account, " \t/\\\x00") {
			return "", false, fmt.Errorf("bad account in subscribe")
		}
		return account, false, nil
	}
	return "", false, fmt.Errorf("not a subscribe datagram")
}

func (r *relay) onDatagram(from *net.UDPAddr, b []byte, now time.Time) {
	account, bye, err := parseSub(b)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if bye {
		if r.client != nil && r.client.String() == from.String() {
			r.stopActiveLocked()
			r.client = nil
			r.logf("audio subscriber %s left", from)
		}
		return
	}
	uid, ok := r.uidCache[account]
	if !ok {
		u, err := r.lookupUID(account)
		if err != nil {
			r.send(from, []byte("SCAU1 status unknown-account "+account))
			return
		}
		uid = u
		r.uidCache[account] = uid
	}
	if r.client == nil || r.client.String() != from.String() || r.clientUID != uid {
		r.stopActiveLocked()
		r.client = from
		r.clientUID = uid
		r.logf("audio subscriber %s wants account %s (uid %d)", from, account, uid)
	}
	r.lastSub = now
	if r.active == nil {
		for a := range r.agents {
			if a.uid == uid {
				r.active = a
				break
			}
		}
	}
	if r.active == nil {
		r.status("no-agent " + account)
		return
	}
	if !r.active.started {
		r.active.cmd(cmdStart)
		r.active.started = true
	}
}

// tick drops a subscriber that stopped renewing (the client died or the tunnel went away).
func (r *relay) tick(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client != nil && now.Sub(r.lastSub) > audioSubTimeout {
		r.logf("audio subscriber %s timed out", r.client)
		r.stopActiveLocked()
		r.client = nil
	}
}
