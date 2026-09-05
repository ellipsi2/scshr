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
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
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
		ioProcPtr = purego.NewCallback(ioProc)
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
	out chan []byte // packets for the relay; dropped when the relay is slow rather than blocking CoreAudio

	procs  []uint32 // process object ids currently tapped
	tap    uint32
	agg    uint32
	ioproc uintptr
	desc   objc.ID

	rate        uint32
	channels    int
	interleaved bool
	seq         uint16
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
		return fmt.Errorf("AudioHardwareCreateProcessTap = %d (System Audio Recording permission?)", st)
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
		return fmt.Errorf("AudioHardwareCreateAggregateDevice = %d", st)
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
		return fmt.Errorf("AudioDeviceCreateIOProcID = %d", st)
	}
	if st := audioDeviceStart(t.agg, t.ioproc); st != 0 {
		return fmt.Errorf("AudioDeviceStart = %d", st)
	}
	log.Printf("tapping %d process(es): %d Hz, %d ch, interleaved=%v", len(procs), t.rate, t.channels, t.interleaved)
	t.status(fmt.Sprintf("tapping %d process(es) at %d Hz", len(procs), t.rate))
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
	if t == nil || inList == 0 {
		return 0
	}
	nbuf := int(*(*uint32)(unsafe.Pointer(inList)))
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
	packetize(pcm, channels, t.rate, &t.seq, func(pkt []byte) {
		select {
		case t.out <- frame(frameAudio, pkt):
		default:
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
	t := &tapper{uid: uint32(os.Getuid()), pid: int32(os.Getpid()), out: make(chan []byte, 256)}
	log.Printf("agent for uid %d ready", t.uid)
	for {
		if err := t.serve(); err != nil {
			log.Printf("relay: %v (retrying)", err)
		}
		t.stop()
		time.Sleep(2 * time.Second)
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
	started := false
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-errs:
			return err
		case cmd := <-cmds:
			switch cmd {
			case cmdStart:
				if !started {
					log.Printf("start requested")
					started = true
					t.poll()
				}
			case cmdStop:
				if started {
					log.Printf("stop requested")
					started = false
					t.stop()
				}
			}
		case <-tick.C:
			if started {
				t.poll()
			}
		case pkt := <-t.out:
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := c.Write(pkt); err != nil {
				return err
			}
		}
	}
}
