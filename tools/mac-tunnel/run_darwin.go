//go:build darwin

package main

// The foreground tunnel. launchd (KeepAlive) supervises this process, so every failure is fatal
// and reported on stderr rather than retried here.

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const mtu = 1420

func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}
	return nil
}

func runTunnel(c *conf) error {
	uapiText, err := c.uapi()
	if err != nil {
		return err
	}

	tdev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return fmt.Errorf("creating a utun interface failed (is this running as root?): %w", err)
	}
	name, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return fmt.Errorf("could not read the utun interface name: %w", err)
	}
	fmt.Printf("scshr-tunnel: interface %s created\n", name)

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("scshr-tunnel(%s) ", name))
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	if err := dev.IpcSet(uapiText); err != nil {
		dev.Close()
		return fmt.Errorf("configuring the tunnel failed: %w", err)
	}
	fmt.Println("scshr-tunnel: configuration applied")

	// Fixed socket name: `status` must find the tunnel without knowing the utun number.
	uapiFile, err := ipc.UAPIOpen(uapiName)
	if err != nil {
		dev.Close()
		return fmt.Errorf("opening %s failed: %w", uapiSocket, err)
	}
	uapiListener, err := ipc.UAPIListen(uapiName, uapiFile)
	if err != nil {
		uapiFile.Close()
		dev.Close()
		return fmt.Errorf("listening on %s failed: %w", uapiSocket, err)
	}
	go func() {
		for {
			c, err := uapiListener.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	if err := dev.Up(); err != nil {
		uapiListener.Close()
		dev.Close()
		return fmt.Errorf("bringing the tunnel up failed: %w", err)
	}

	// Same interface configuration wg-quick performs on darwin, and nothing more: one host
	// address and, when paired, exactly one /32 route to the peer. No default route, no DNS.
	addr := c.Address.String()
	cleanupRoute := false
	teardown := func() {
		if cleanupRoute {
			_ = sh("route", "-q", "-n", "delete", "-inet", c.PeerAllowedIP.String()+"/32", "-interface", name)
		}
		uapiListener.Close()
		dev.Close()
		os.Remove(utunNameFil)
	}

	if err := sh("ifconfig", name, "inet", addr+"/32", addr, "alias"); err != nil {
		teardown()
		return err
	}
	if err := sh("ifconfig", name, "mtu", fmt.Sprint(mtu)); err != nil {
		teardown()
		return err
	}
	if err := sh("ifconfig", name, "up"); err != nil {
		teardown()
		return err
	}
	fmt.Printf("scshr-tunnel: %s configured with %s/32 mtu %d\n", name, addr, mtu)

	if c.HasPeer {
		peer := c.PeerAllowedIP.String() + "/32"
		if err := sh("route", "-q", "-n", "add", "-inet", peer, "-interface", name); err != nil {
			teardown()
			return err
		}
		cleanupRoute = true
		fmt.Printf("scshr-tunnel: route %s via %s\n", peer, name)
	}

	if err := os.WriteFile(utunNameFil, []byte(name+"\n"), 0o644); err != nil {
		teardown()
		return fmt.Errorf("recording the interface name failed: %w", err)
	}
	fmt.Printf("scshr-tunnel: listening on udp/%d\n", c.ListenPort)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-stop:
	case <-dev.Wait():
	}
	fmt.Println("scshr-tunnel: shutting down")
	teardown()
	return nil
}

