//go:build !darwin

package main

import "fmt"

func cmdAudioAgent() error { return fmt.Errorf("audio-agent is only supported on macOS") }

func cmdAudioTapTest([]string) error { return fmt.Errorf("audio-tap-test is only supported on macOS") }
