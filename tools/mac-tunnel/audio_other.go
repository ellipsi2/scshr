//go:build !darwin

package main

import "fmt"

func cmdAudioAgent() error { return fmt.Errorf("audio-agent is only supported on macOS") }
