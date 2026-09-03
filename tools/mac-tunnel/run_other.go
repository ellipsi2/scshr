//go:build !darwin

package main

import "fmt"

// The tunnel itself only exists on macOS; the parser, key and status commands stay portable so
// they can be tested and vetted on any host.
func runTunnel(c *conf) error {
	return fmt.Errorf("run is only supported on macOS")
}
