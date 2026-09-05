package main

import "encoding/binary"

// packetize turns interleaved float32 PCM (channels 1 or 2) into relay audio packets: 16-byte header +
// int16le stereo samples, at most audioMaxFrames frames each. Silent chunks are skipped entirely — the
// receiver's jitter buffer already plays silence on underflow, and most of the time nothing plays.
func packetize(pcm []float32, channels int, rate uint32, seq *uint16, emit func([]byte)) {
	if channels < 1 {
		return
	}
	frames := len(pcm) / channels
	for off := 0; off < frames; off += audioMaxFrames {
		n := frames - off
		if n > audioMaxFrames {
			n = audioMaxFrames
		}
		pkt := make([]byte, audioHeaderLen+n*4)
		copy(pkt, audioMagic)
		pkt[4] = 1
		pkt[5] = 2
		binary.LittleEndian.PutUint16(pkt[6:], *seq)
		binary.LittleEndian.PutUint32(pkt[8:], rate)
		binary.LittleEndian.PutUint16(pkt[12:], uint16(n))
		silent := true
		for i := 0; i < n; i++ {
			l := pcm[(off+i)*channels]
			r := l
			if channels > 1 {
				r = pcm[(off+i)*channels+1]
			}
			if l != 0 || r != 0 {
				silent = false
			}
			binary.LittleEndian.PutUint16(pkt[audioHeaderLen+i*4:], uint16(toInt16(l)))
			binary.LittleEndian.PutUint16(pkt[audioHeaderLen+i*4+2:], uint16(toInt16(r)))
		}
		if silent {
			continue
		}
		*seq++
		emit(pkt)
	}
}

func toInt16(f float32) int16 {
	if f >= 1 {
		return 32767
	}
	if f <= -1 {
		return -32768
	}
	return int16(f * 32767)
}
