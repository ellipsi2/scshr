//go:build darwin

package main

// `scshr-tunnel audio-agent`: the per-user half of session audio. launchd runs one instance in every
// GUI login session (/Library/LaunchAgents/net.scshr.audio.plist). It connects to the relay in the root
// tunnel daemon and, only while the relay says so, taps the audio of every process running as this
// account through a CoreAudio process tap (macOS 14.2+), muted locally: the remote user's sound goes
// to the Windows client and nowhere else, while the person at the Mac keeps hearing only their own.
//
// CoreAudio is reached through purego (no cgo: this binary is cross-compiled from Windows), which is
// why the Objective-C CATapDescription is driven through objc_msgSend by selector.
//
// The first tap this account ever creates makes macOS ask "scshr-tunnel would like to record this
// computer's audio" — inside the remote session, so the remote user answers it. A refusal is not
// reported by CoreAudio; the tap simply delivers silence.

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
	"golang.org/x/sys/unix"
)

// ── CoreAudio bindings ────────────────────────────────────────────────────────────────────────

const (
	kAudioObjectSystemObject                = 1
	kAudioHardwarePropertyProcessObjectList = 0x70727323 // 'prs#'
	kAudioProcessPropertyPID                = 0x70706964 // 'ppid'
	kAudioTapPropertyFormat                 = 0x74666d74 // 'tfmt'
	kAudioObjectPropertyScopeGlobal         = 0x676c6f62 // 'glob'
	kAudioObjectPropertyElementMain         = 0
	kAudioFormatFlagIsFloat                 = 1 << 0
	kAudioFormatFlagIsNonInterleaved        = 1 << 5
	// CATapMuteBehavior: CATapUnmuted = 0, CATapMuted = 1, CATapMutedWhenTapped = 2 — the tapped
	// processes stay audible on the Mac until the tap is being read, and come back when it stops.
	catapMutedWhenTapped = 2
)

type propAddr struct{ selector, scope, element uint32 }

// AudioStreamBasicDescription (40 bytes).
type asbd struct {
	SampleRate       float64
	FormatID         uint32
	FormatFlags      uint32
	BytesPerPacket   uint32
	FramesPerPacket  uint32
	BytesPerFrame    uint32
	ChannelsPerFrame uint32
	BitsPerChannel   uint32
	Reserved         uint32
}

var (
	caOnce sync.Once
	caErr  error

	audioObjectGetPropertyDataSize      func(obj uint32, addr *propAddr, qsize uint32, qdata unsafe.Pointer, size *uint32) int32
	audioObjectGetPropertyData          func(obj uint32, addr *propAddr, qsize uint32, qdata unsafe.Pointer, size *uint32, out unsafe.Pointer) int32
	audioHardwareCreateProcessTap       func(desc objc.ID, out *uint32) int32
	audioHardwareDestroyProcessTap      func(tap uint32) int32
	audioHardwareCreateAggregateDevice  func(desc objc.ID, out *uint32) int32
	audioHardwareDestroyAggregateDevice func(dev uint32) int32
	audioDeviceCreateIOProcID           func(dev uint32, proc uintptr, client unsafe.Pointer, out *uintptr) int32
	audioDeviceDestroyIOProcID          func(dev uint32, proc uintptr) int32
	audioDeviceStart                    func(dev uint32, proc uintptr) int32
	audioDeviceStop                     func(dev uint32, proc uintptr) int32

	clsTapDescription, clsString, clsNumber, clsMutableArray, clsMutableDictionary, clsAutoreleasePool objc.Class
	selAlloc, selNew, selDrain, selRelease, selInitStereoMixdown, selSetName, selSetPrivate, selSetMuteBehavior,
	selUUID, selUUIDString, selUTF8String, selStringWithUTF8String, selNumberWithBool, selNumberWithUnsignedInt,
	selArray, selAddObject, selDictionary, selSetObjectForKey objc.SEL

	ioProcPtr uintptr

	// Read-only permission preflight (TCC.framework; the call AudioCap uses) and the session's console flag.
	tccAccessPreflight             func(service objc.ID, options objc.ID) int32
	cgSessionCopyCurrentDictionary func() objc.ID
	selObjectForKey, selBoolValue  objc.SEL
)

const (
	tccGranted             = 0 // TCCAccessPreflight: 0 granted, 1 undetermined, 2 denied
	tccUnknown             = 1
	tccAudioCaptureService = "kTCCServiceAudioCapture"
)

func loadCoreAudio() error {
	caOnce.Do(func() {
		if _, err := purego.Dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
			caErr = err
			return
		}
		ca, err := purego.Dlopen("/System/Library/Frameworks/CoreAudio.framework/CoreAudio", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			caErr = err
			return
		}
		defer func() {
			if r := recover(); r != nil { // RegisterLibFunc panics on a missing symbol (pre-14.2 macOS)
				caErr = fmt.Errorf("CoreAudio process taps unavailable (macOS 14.2 or newer needed): %v", r)
			}
		}()
		purego.RegisterLibFunc(&audioObjectGetPropertyDataSize, ca, "AudioObjectGetPropertyDataSize")
		purego.RegisterLibFunc(&audioObjectGetPropertyData, ca, "AudioObjectGetPropertyData")
		purego.RegisterLibFunc(&audioHardwareCreateProcessTap, ca, "AudioHardwareCreateProcessTap")
		purego.RegisterLibFunc(&audioHardwareDestroyProcessTap, ca, "AudioHardwareDestroyProcessTap")
		purego.RegisterLibFunc(&audioHardwareCreateAggregateDevice, ca, "AudioHardwareCreateAggregateDevice")
		purego.RegisterLibFunc(&audioHardwareDestroyAggregateDevice, ca, "AudioHardwareDestroyAggregateDevice")
		purego.RegisterLibFunc(&audioDeviceCreateIOProcID, ca, "AudioDeviceCreateIOProcID")
		purego.RegisterLibFunc(&audioDeviceDestroyIOProcID, ca, "AudioDeviceDestroyIOProcID")
		purego.RegisterLibFunc(&audioDeviceStart, ca, "AudioDeviceStart")
		purego.RegisterLibFunc(&audioDeviceStop, ca, "AudioDeviceStop")

		clsTapDescription = objc.GetClass("CATapDescription")
		if clsTapDescription == 0 {
			caErr = fmt.Errorf("CATapDescription is missing (macOS 14.2 or newer needed)")
			return
		}
		clsString = objc.GetClass("NSString")
		clsNumber = objc.GetClass("NSNumber")
		clsMutableArray = objc.GetClass("NSMutableArray")
		clsMutableDictionary = objc.GetClass("NSMutableDictionary")
		clsAutoreleasePool = objc.GetClass("NSAutoreleasePool")
		selAlloc = objc.RegisterName("alloc")
		selNew = objc.RegisterName("new")
		selDrain = objc.RegisterName("drain")
		selRelease = objc.RegisterName("release")
		selInitStereoMixdown = objc.RegisterName("initStereoMixdownOfProcesses:")
		selSetName = objc.RegisterName("setName:")
		selSetPrivate = objc.RegisterName("setPrivate:")
		selSetMuteBehavior = objc.RegisterName("setMuteBehavior:")
		selUUID = objc.RegisterName("UUID")
		selUUIDString = objc.RegisterName("UUIDString")
		selUTF8String = objc.RegisterName("UTF8String")
		selStringWithUTF8String = objc.RegisterName("stringWithUTF8String:")
		selNumberWithBool = objc.RegisterName("numberWithBool:")
		selNumberWithUnsignedInt = objc.RegisterName("numberWithUnsignedInt:")
		selArray = objc.RegisterName("array")
		selAddObject = objc.RegisterName("addObject:")
		selDictionary = objc.RegisterName("dictionary")
		selSetObjectForKey = objc.RegisterName("setObject:forKey:")
		selObjectForKey = objc.RegisterName("objectForKey:")
		selBoolValue = objc.RegisterName("boolValue")
		ioProcPtr = purego.NewCallback(ioProc)
		// Optional: without these the agent still works, it just cannot preflight or detect the console.
		if tcc, err := purego.Dlopen("/System/Library/PrivateFrameworks/TCC.framework/TCC", purego.RTLD_NOW|purego.RTLD_GLOBAL); err == nil {
			func() {
				defer func() { recover() }()
				purego.RegisterLibFunc(&tccAccessPreflight, tcc, "TCCAccessPreflight")
			}()
		}
		if cg, err := purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL); err == nil {
			func() {
				defer func() { recover() }()
				purego.RegisterLibFunc(&cgSessionCopyCurrentDictionary, cg, "CGSessionCopyCurrentDictionary")
			}()
		}
	})
	return caErr
}

func cstr(s string) *byte { b := append([]byte(s), 0); return &b[0] }
func nsString(s string) objc.ID { return objc.ID(clsString).Send(selStringWithUTF8String, cstr(s)) }
func nsBool(b bool) objc.ID     { return objc.ID(clsNumber).Send(selNumberWithBool, b) }
func nsU32(v uint32) objc.ID    { return objc.ID(clsNumber).Send(selNumberWithUnsignedInt, v) }

func nsArray(items ...objc.ID) objc.ID {
	a := objc.ID(clsMutableArray).Send(selArray)
	for _, it := range items {
		a.Send(selAddObject, it)
	}
	return a
}

// nsDict builds an NSMutableDictionary from key, value, key, value … (keys are Go strings).
func nsDict(kv ...any) objc.ID {
	d := objc.ID(clsMutableDictionary).Send(selDictionary)
	for i := 0; i+1 < len(kv); i += 2 {
		d.Send(selSetObjectForKey, kv[i+1].(objc.ID), nsString(kv[i].(string)))
	}
	return d
}

func goString(ns objc.ID) string {
	p := objc.Send[uintptr](ns, selUTF8String)
	var b []byte
	for p != 0 {
		c := *(*byte)(unsafe.Pointer(p))
		if c == 0 {
			break
		}
		b = append(b, c)
		p++
	}
	return string(b)
}

// osstatus renders a CoreAudio OSStatus as its four-character code ('!obj', 'what', …).
func osstatus(st int32) string {
	u := uint32(st)
	b := []byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return fmt.Sprintf("%d", st)
		}
	}
	return fmt.Sprintf("'%s' (%d)", b, st)
}

// audioPermission asks tccd (read-only) whether this process may record system audio.
// tccUnknown when the preflight call is unavailable.
func audioPermission() int32 {
	if tccAccessPreflight == nil {
		return tccUnknown
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := objc.ID(clsAutoreleasePool).Send(selNew)
	defer pool.Send(selDrain)
	return tccAccessPreflight(nsString(tccAudioCaptureService), 0)
}

// sessionOnConsole reports whether this GUI session owns the physical console: false for a
// screen-sharing virtual-display session and for a switched-away user; true when unknown, so an
// undetectable session is treated like the console user's and never muted without a subscriber.
func sessionOnConsole() bool {
	if cgSessionCopyCurrentDictionary == nil {
		return true
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := objc.ID(clsAutoreleasePool).Send(selNew)
	defer pool.Send(selDrain)
	d := cgSessionCopyCurrentDictionary()
	if d == 0 {
		return true
	}
	defer d.Send(selRelease)
	v := d.Send(selObjectForKey, nsString("kCGSSessionOnConsoleKey"))
	if v == 0 {
		return true
	}
	return objc.Send[bool](v, selBoolValue)
}

// askForPermission shows a dialog in this session (osascript runs inside the GUI session, unlike
// tccd's own prompt, which macOS cancels while the session is off-console) and, on request, opens
// the Privacy pane at Screen & System Audio Recording.
func askForPermission() {
	script := `display dialog "To play this session's sound on your Windows PC, scshr needs the System Audio Recording permission for scshr-tunnel." & return & return & "Open System Settings > Privacy & Security > Screen & System Audio Recording and turn on scshr-tunnel. Sound starts by itself once it is on." with title "scshr" buttons {"Later", "Open Settings"} default button "Open Settings" with icon caution`
	out, err := exec.Command("/usr/bin/osascript", "-e", script).Output()
	if err != nil {
		log.Printf("permission dialog: %v", err)
		return
	}
	if strings.Contains(string(out), "Open Settings") {
		_ = exec.Command("/usr/bin/open", "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AudioCapture").Run()
	}
}

func getProp(obj uint32, sel uint32, out unsafe.Pointer, size uint32) error {
	addr := propAddr{sel, kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyElementMain}
	if st := audioObjectGetPropertyData(obj, &addr, 0, nil, &size, out); st != 0 {
		return fmt.Errorf("AudioObjectGetPropertyData(%#x on %d) = %d", sel, obj, st)
	}
	return nil
}

// ── the tap ───────────────────────────────────────────────────────────────────────────────────

type tapper struct {
	uid uint32
	pid int32
	out     chan []byte   // packets for the relay; dropped when the relay is slow rather than blocking CoreAudio
	stopReq chan struct{} // SIGTERM: tear down on the serving goroutine, then exit

	procs  []uint32 // process object ids currently tapped
	tap    uint32
	agg    uint32
	ioproc uintptr
	desc   objc.ID

	rate        uint32
	channels    int
	interleaved bool
	seq         uint16
	diag        bool // audio-tap-test: measure the captured PCM
	tapSince    time.Time // first build of this start
	firstCall   time.Time // first IOProc callback seen with zero samples (silence timer)
	hinted      bool
	forward     atomic.Bool // a subscriber is listening; otherwise the tap only keeps this session muted

	// counters (agent log every 10 s while started; audio-tap-test)
	ioCalls, ioBuffers, ioBytes, ioLoud, ioSamples, ioNonZero, sent, dropped atomic.Uint64
	diagMu   sync.Mutex
	diagPeak float64
	diagSum2 float64
}

// One process, one tap: the IOProc has no room for a Go pointer, so it finds its tapper here.
var activeTapper atomic.Pointer[tapper]

// ownAudioProcesses lists the CoreAudio process objects whose owner is this account (except us).
func (t *tapper) ownAudioProcesses() ([]uint32, error) {
	addr := propAddr{kAudioHardwarePropertyProcessObjectList, kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyElementMain}
	var size uint32
	if st := audioObjectGetPropertyDataSize(kAudioObjectSystemObject, &addr, 0, nil, &size); st != 0 {
		return nil, fmt.Errorf("process list size = %d", st)
	}
	if size == 0 {
		return nil, nil
	}
	ids := make([]uint32, size/4)
	if st := audioObjectGetPropertyData(kAudioObjectSystemObject, &addr, 0, nil, &size, unsafe.Pointer(&ids[0])); st != 0 {
		return nil, fmt.Errorf("process list = %d", st)
	}
	ids = ids[:size/4]
	var own []uint32
	for _, id := range ids {
		var pid int32
		if err := getProp(id, kAudioProcessPropertyPID, unsafe.Pointer(&pid), 4); err != nil || pid <= 0 || pid == t.pid {
			continue
		}
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
		if err != nil || kp.Eproc.Ucred.Uid != t.uid {
			continue
		}
		own = append(own, id)
	}
	slices.Sort(own)
	return own, nil
}

// A tap whose owner lacks the System Audio Recording permission is not an error: CoreAudio runs the
// IOProc and hands over zeros (seen on macOS 26.6, TCC auth_reason PROMPT_CANCEL because the prompt
// cannot be shown in a session that is off console, which a screen-sharing virtual display session
// is). Tell the subscriber where the switch lives once the tap has run silently for this long.
const (
	silentTapHint    = 4 * time.Second
	silentTapRestart = 12 * time.Second // first restart; doubles per consecutive silent restart, capped
	silentRestartCap = 5 * time.Minute
)

var permissionHint = "sound is playing in this session but macOS hands scshr only silence: on the Mac, in this session, open System Settings > Privacy & Security > Screen & System Audio Recording and turn on scshr-tunnel (macOS cannot show the permission prompt in a screen-sharing session); scshr retries by itself"

// coreaudiod decides the permission once per client process: a grant made while this agent was
// already running is never seen by it (observed live: zeros until the agent was restarted, audio
// immediately after). So a tap that stays silent makes the agent exit; launchd (KeepAlive) starts a
// fresh process, the relay re-starts it on the next subscribe, and macOS re-evaluates. Genuine
// silence would do the same, so the wait doubles per consecutive silent restart (state in a file,
// reset as soon as sound arrives).
func silentRestartFile(uid uint32) string { return fmt.Sprintf("/tmp/scshr-audio-%d.silent-restarts", uid) }

func (t *tapper) silentRestarts() int {
	b, err := os.ReadFile(silentRestartFile(t.uid))
	if err != nil {
		return 0
	}
	n := 0
	fmt.Sscan(string(b), &n)
	return n
}

func (t *tapper) checkSilence() {
	// With tapautostart the aggregate device only runs IO while a tapped process is producing output:
	// no callbacks at all just means nothing is playing in this session (seen live: zero callbacks with
	// the session idle, callbacks the moment `say` spoke). Callbacks that carry only zeros are the
	// signature of a missing System Audio Recording grant.
	if t.tap == 0 || t.tapSince.IsZero() || t.ioCalls.Load() == 0 {
		return
	}
	if t.ioLoud.Load() > 0 {
		if t.silentRestarts() > 0 {
			os.Remove(silentRestartFile(t.uid))
		}
		return
	}
	if t.firstCall.IsZero() {
		t.firstCall = time.Now()
		return
	}
	silent := time.Since(t.firstCall)
	if !t.hinted && silent >= silentTapHint {
		t.hinted = true
		log.Printf("%s", permissionHint)
		t.status(permissionHint)
	}
	n := t.silentRestarts()
	wait := silentTapRestart << uint(min(n, 8))
	if wait > silentRestartCap {
		wait = silentRestartCap
	}
	if silent >= wait {
		log.Printf("tap silent for %s (silent restart #%d): exiting so macOS re-evaluates the recording permission for a fresh process", silent.Truncate(time.Second), n+1)
		_ = os.WriteFile(silentRestartFile(t.uid), []byte(fmt.Sprint(n+1)), 0o644)
		t.teardown()
		os.Exit(0)
	}
}

// poll keeps the tap in step with the account's audio processes; called once a second while started.
// A changed process set rebuilds the tap (a few tens of milliseconds of silence — only when an
// audio-using app starts or quits).
func (t *tapper) poll() {
	procs, err := t.ownAudioProcesses()
	if err != nil {
		log.Printf("process list: %v", err)
		return
	}
	if slices.Equal(procs, t.procs) && (t.tap != 0 || len(procs) == 0) {
		return
	}
	t.teardown()
	t.procs = procs
	if len(procs) == 0 {
		return
	}
	if err := t.build(procs); err != nil {
		log.Printf("tap: %v", err)
		t.teardown()
		t.procs = nil
	}
}

func (t *tapper) build(procs []uint32) error {
	// NSAutoreleasePool is per OS thread and Go moves goroutines between threads: the pool must be
	// drained on the thread that created it (draining elsewhere crashed on macOS 26.6).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := objc.ID(clsAutoreleasePool).Send(selNew)
	defer pool.Send(selDrain)

	nums := make([]objc.ID, len(procs))
	for i, p := range procs {
		nums[i] = nsU32(p)
	}
	desc := objc.ID(clsTapDescription).Send(selAlloc).Send(selInitStereoMixdown, nsArray(nums...))
	if desc == 0 {
		return fmt.Errorf("CATapDescription init failed")
	}
	desc.Send(selSetName, nsString("scshr session audio"))
	desc.Send(selSetPrivate, true)
	desc.Send(selSetMuteBehavior, int(catapMutedWhenTapped))
	t.desc = desc

	if st := audioHardwareCreateProcessTap(desc, &t.tap); st != 0 {
		// Not a permission failure: without the System Audio Recording permission the tap is created
		// and delivers silence. '!obj' means a listed process object is gone (it exited between the
		// listing and now); the next poll lists afresh.
		return fmt.Errorf("AudioHardwareCreateProcessTap failed: %s", osstatus(st))
	}
	uuid := goString(desc.Send(selUUID).Send(selUUIDString))
	// Private aggregate device that contains nothing but the tap (the layout Chromium and multimon
	// ship): its input stream is the stereo mixdown of the tapped processes.
	dict := nsDict(
		"name", nsString("scshr session audio"),
		"uid", nsString("net.scshr.audio."+uuid),
		"private", nsBool(true),
		"tapautostart", nsBool(true),
		"taps", nsArray(nsDict("uid", nsString(uuid), "drift", nsBool(true))),
	)
	if st := audioHardwareCreateAggregateDevice(dict, &t.agg); st != 0 {
		return fmt.Errorf("AudioHardwareCreateAggregateDevice failed: %s", osstatus(st))
	}
	var fmtd asbd
	if err := getProp(t.tap, kAudioTapPropertyFormat, unsafe.Pointer(&fmtd), uint32(unsafe.Sizeof(fmtd))); err != nil {
		return err
	}
	if fmtd.FormatFlags&kAudioFormatFlagIsFloat == 0 || fmtd.BitsPerChannel != 32 {
		return fmt.Errorf("tap format is not float32 (flags %#x, %d bits)", fmtd.FormatFlags, fmtd.BitsPerChannel)
	}
	t.rate = uint32(fmtd.SampleRate)
	t.channels = int(fmtd.ChannelsPerFrame)
	t.interleaved = fmtd.FormatFlags&kAudioFormatFlagIsNonInterleaved == 0
	if t.channels < 1 || t.rate < 8000 {
		return fmt.Errorf("unusable tap format: %d ch %d Hz", t.channels, t.rate)
	}
	activeTapper.Store(t)
	if st := audioDeviceCreateIOProcID(t.agg, ioProcPtr, nil, &t.ioproc); st != 0 {
		return fmt.Errorf("AudioDeviceCreateIOProcID failed: %s", osstatus(st))
	}
	if st := audioDeviceStart(t.agg, t.ioproc); st != 0 {
		return fmt.Errorf("AudioDeviceStart failed: %s", osstatus(st))
	}
	log.Printf("tapping %d process(es): %d Hz, %d ch, interleaved=%v", len(procs), t.rate, t.channels, t.interleaved)
	t.status(fmt.Sprintf("tapping %d process(es) at %d Hz", len(procs), t.rate))
	if t.tapSince.IsZero() {
		t.tapSince = time.Now()
	}
	return nil
}

func (t *tapper) teardown() {
	if t.agg != 0 && t.ioproc != 0 {
		audioDeviceStop(t.agg, t.ioproc)
		audioDeviceDestroyIOProcID(t.agg, t.ioproc)
	}
	activeTapper.Store(nil)
	t.ioproc = 0
	if t.agg != 0 {
		audioHardwareDestroyAggregateDevice(t.agg)
		t.agg = 0
	}
	if t.tap != 0 {
		audioHardwareDestroyProcessTap(t.tap)
		t.tap = 0
	}
	if t.desc != 0 {
		t.desc.Send(selRelease)
		t.desc = 0
	}
}

func (t *tapper) stop() {
	if t.tap != 0 {
		log.Printf("tap stopped")
	}
	t.teardown()
	t.procs = nil
	t.tapSince = time.Time{}
	t.firstCall = time.Time{}
	t.hinted = false
	t.ioLoud.Store(0)
	t.ioCalls.Store(0)
}

func (t *tapper) status(text string) {
	select {
	case t.out <- frame(frameStatus, []byte(text)):
	default:
	}
}

func frame(kind byte, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = kind
	binary.LittleEndian.PutUint32(b[1:], uint32(len(payload)))
	copy(b[5:], payload)
	return b
}

// ioProc runs on CoreAudio's realtime thread: AudioDeviceIOProc(inDevice, inNow, inInputData,
// inInputTime, outOutputData, outOutputTime, inClientData). The AudioBufferList is
// { UInt32 mNumberBuffers; AudioBuffer mBuffers[]; } at offset 8, each buffer
// { UInt32 mNumberChannels; UInt32 mDataByteSize; void* mData; } (16 bytes).
func ioProc(dev uint32, now, inList, inTime, outList, outTime, client uintptr) int32 {
	t := activeTapper.Load()
	if t == nil {
		return 0
	}
	t.ioCalls.Add(1)
	if inList == 0 {
		return 0
	}
	nbuf := int(*(*uint32)(unsafe.Pointer(inList)))
	t.ioBuffers.Add(uint64(nbuf))
	if nbuf == 0 {
		return 0
	}
	buf := func(i int) (channels int, data []float32) {
		p := inList + 8 + uintptr(i)*16
		channels = int(*(*uint32)(unsafe.Pointer(p)))
		bytes := int(*(*uint32)(unsafe.Pointer(p + 4)))
		ptr := *(*unsafe.Pointer)(unsafe.Pointer(p + 8))
		if ptr == nil || bytes < 4 {
			return channels, nil
		}
		return channels, unsafe.Slice((*float32)(ptr), bytes/4)
	}
	var pcm []float32
	channels := t.channels
	if t.interleaved {
		ch, data := buf(0)
		if ch > 0 {
			channels = ch
		}
		pcm = data
	} else {
		// One buffer per channel: interleave the first two.
		_, l := buf(0)
		var r []float32
		if nbuf > 1 {
			_, r = buf(1)
		} else {
			r = l
		}
		n := min(len(l), len(r))
		pcm = make([]float32, 2*n)
		for i := 0; i < n; i++ {
			pcm[2*i] = l[i]
			pcm[2*i+1] = r[i]
		}
		channels = 2
	}
	if len(pcm) == 0 {
		return 0
	}
	t.ioBytes.Add(uint64(len(pcm) * 4))
	t.ioSamples.Add(uint64(len(pcm)))
	if !t.diag {
		for _, v := range pcm {
			if v != 0 {
				t.ioLoud.Add(1)
				break
			}
		}
	}
	if t.diag {
		var nz uint64
		peak, sum2 := 0.0, 0.0
		for _, v := range pcm {
			if v != 0 {
				nz++
			}
			a := float64(v)
			if a < 0 {
				a = -a
			}
			if a > peak {
				peak = a
			}
			sum2 += a * a
		}
		if nz > 0 {
			t.ioLoud.Add(1)
			t.ioNonZero.Add(nz)
		}
		t.diagMu.Lock()
		if peak > t.diagPeak {
			t.diagPeak = peak
		}
		t.diagSum2 += sum2
		t.diagMu.Unlock()
	}
	if !t.forward.Load() {
		return 0 // standby: muting only, nothing to send
	}
	packetize(pcm, channels, t.rate, &t.seq, func(pkt []byte) {
		select {
		case t.out <- frame(frameAudio, pkt):
			t.sent.Add(1)
		default:
			t.dropped.Add(1)
		}
	})
	return 0
}

// ── the agent process ─────────────────────────────────────────────────────────────────────────

func cmdAudioAgent() error {
	if home, err := os.UserHomeDir(); err == nil {
		dir := filepath.Join(home, "Library", "Logs")
		_ = os.MkdirAll(dir, 0o755)
		if f, err := os.OpenFile(filepath.Join(dir, "scshr-audio.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			log.SetOutput(io.MultiWriter(os.Stderr, f))
		}
	}
	log.SetPrefix("scshr-audio: ")
	if err := loadCoreAudio(); err != nil {
		// launchd (KeepAlive) would restart us in a loop; sleep so the log stays readable.
		log.Printf("%v", err)
		time.Sleep(time.Hour)
		return err
	}
	t := &tapper{uid: uint32(os.Getuid()), pid: int32(os.Getpid()), out: make(chan []byte, 256), stopReq: make(chan struct{}, 1)}
	// launchd stops us with SIGTERM (bootout, kickstart -k): release the tap first, otherwise the
	// successor may build over devices coreaudiod is still tearing down.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		log.Printf("terminating: releasing the tap")
		t.stopReq <- struct{}{}
	}()
	log.Printf("agent for uid %d ready", t.uid)
	for {
		if err := t.serve(); err != nil {
			log.Printf("relay: %v (retrying)", err)
		}
		t.stop()
		select { // launchd's SIGTERM must not wait out the reconnect pause
		case <-t.stopReq:
			os.Exit(0)
		case <-time.After(2 * time.Second):
		}
	}
}

// serve talks to the relay until the connection drops. The tap itself is only touched from this
// goroutine (commands and the once-a-second poll are serialised through one select).
func (t *tapper) serve() error {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: audioAgentSocket, Net: "unix"})
	if err != nil {
		return err
	}
	defer c.Close()
	log.Printf("connected to the relay")
	cmds := make(chan byte)
	errs := make(chan error, 1)
	go func() {
		b := make([]byte, 1)
		for {
			if _, err := c.Read(b); err != nil {
				errs <- err
				return
			}
			cmds <- b[0]
		}
	}()
	// The tap runs while a subscriber listens (started) and, once this session is known to be the remote
	// one, also on standby: a screen-sharing virtual-display session is off-console, and its sound must
	// not come out of the Mac's speakers between scshr connections either. Standby needs the permission
	// (an unpermitted tap does not mute) and ends the moment the session is on console.
	started, standby, asked := false, false, false
	granted := audioPermission() == tccGranted
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	stats := time.NewTicker(10 * time.Second)
	defer stats.Stop()
	ticks := 0
	if granted && !sessionOnConsole() {
		standby = true
		log.Printf("off-console session with permission: standby tap (mute only)")
		t.poll()
	}
	for {
		select {
		case err := <-errs:
			return err
		case <-t.stopReq:
			t.stop()
			os.Exit(0)
		case <-stats.C:
			if t.tap != 0 {
				log.Printf("stats: ioproc=%d non-silent=%d packets sent=%d dropped=%d forwarding=%v", t.ioCalls.Load(), t.ioLoud.Load(), t.sent.Load(), t.dropped.Load(), t.forward.Load())
			}
		case cmd := <-cmds:
			switch cmd {
			case cmdStart:
				if !started {
					log.Printf("start requested")
					started = true
					t.forward.Store(true)
					t.poll()
					if p := audioPermission(); p != tccGranted {
						log.Printf("audio permission preflight: %d (0 granted, 1 undetermined, 2 denied)", p)
						t.status(permissionHint)
						if !asked {
							asked = true
							go askForPermission()
						}
					}
				}
			case cmdStop:
				if started {
					log.Printf("stop requested")
					started = false
					t.forward.Store(false)
					if sessionOnConsole() || audioPermission() != tccGranted {
						t.stop()
					} else {
						standby = true
						log.Printf("subscriber gone: keeping the tap on standby so this session stays silent on the Mac")
					}
				}
			}
		case <-tick.C:
			ticks++
			if ticks%5 == 0 { // permission and console state, every 5 s
				now := audioPermission() == tccGranted
				if now && !granted {
					// Granted while running: coreaudiod decided for this process already; a fresh process
					// gets the grant, and the relay restarts us on its next subscribe.
					log.Printf("permission granted: restarting to apply it")
					t.stop()
					os.Exit(0)
				}
				granted = now
				onConsole := sessionOnConsole()
				if standby && onConsole {
					standby = false
					if !started {
						log.Printf("session is on console now: releasing the standby tap")
						t.stop()
					}
				}
				if !started && !standby && granted && !onConsole && asked {
					standby = true // identified as the remote session earlier in this process
					t.poll()
				}
			}
			if started || standby {
				t.poll()
			}
			if started {
				t.checkSilence()
			}
		case pkt := <-t.out:
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := c.Write(pkt); err != nil {
				return err
			}
		}
	}
}

// cmdAudioTapTest taps this account's audio processes for a few seconds and reports what
// happened — the on-Mac check for the CoreAudio bindings, the permission prompt and the mute.
//   launchctl asuser <uid> sudo -u <user> scshr-tunnel audio-tap-test [seconds]
func cmdAudioTapTest(args []string) error {
	secs := 10
	if len(args) > 0 {
		fmt.Sscan(args[0], &secs)
	}
	log.SetOutput(os.Stderr)
	log.SetPrefix("scshr-audio-test: ")
	if err := loadCoreAudio(); err != nil {
		return err
	}
	static := os.Getenv("SCSHR_TAP_STATIC") == "1"   // tap the process set found at start and never rebuild
	t := &tapper{uid: uint32(os.Getuid()), pid: int32(os.Getpid()), out: make(chan []byte, 256), diag: true}
	procs, err := t.ownAudioProcesses()
	if err != nil {
		return err
	}
	pids := make([]int32, 0, len(procs))
	for _, id := range procs {
		var pid int32
		_ = getProp(id, kAudioProcessPropertyPID, unsafe.Pointer(&pid), 4)
		pids = append(pids, pid)
	}
	log.Printf("uid %d: %d audio process object(s) owned: objects=%v pids=%v static=%v", t.uid, len(procs), procs, pids, static)
	t.poll()
	if t.tap == 0 {
		log.Printf("no tap created (see errors above, or no audio process is running as this account)")
	}
	deadline := time.After(time.Duration(secs) * time.Second)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	pkts, frames := 0, 0
	for {
		select {
		case <-deadline:
			calls, loud := t.ioCalls.Load(), t.ioLoud.Load()
			t.stop()
			samples := t.ioSamples.Load()
			t.diagMu.Lock()
			rms := 0.0
			if samples > 0 {
				rms = math.Sqrt(t.diagSum2 / float64(samples))
			}
			log.Printf("done: %d audio packet(s), %d frame(s) sent; ioproc calls=%d buffers=%d bytes=%d samples=%d non-zero samples=%d non-silent callbacks=%d peak=%.5f rms=%.6f",
				pkts, frames, calls, t.ioBuffers.Load(), t.ioBytes.Load(), samples, t.ioNonZero.Load(), loud, t.diagPeak, rms)
			t.diagMu.Unlock()
			if n := os.Getenv("SCSHR_TAP_REBUILDS"); n != "" {
				var k int
				fmt.Sscan(n, &k)
				for i := 0; i < k; i++ {
					t.teardown()
					fresh, err := t.ownAudioProcesses() // a stale list holds exited processes → '!obj'
					if err == nil && len(fresh) > 0 {
						err = t.build(fresh)
					}
					if err != nil {
						log.Printf("rebuild %d: %v", i+1, err)
					}
				}
				t.teardown()
				log.Printf("%d teardown/build cycles completed without a crash", k)
			}
			return nil
		case <-tick.C:
			if !static {
				t.poll()
			}
			t.checkSilence()
		case b := <-t.out:
			if b[0] == frameAudio {
				pkts++
				frames += int(binary.LittleEndian.Uint16(b[5+12:]))
				if pkts == 1 {
					log.Printf("first audio packet: %d bytes", len(b)-5)
				}
			} else {
				log.Printf("status: %s", b[5:])
			}
		}
	}
}

