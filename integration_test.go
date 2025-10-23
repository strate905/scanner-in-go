package main

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIntegrationTCPScan(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if shouldSkipListen(err) {
			t.Skipf("skipping TCP integration test: %v", err)
		}
		t.Fatalf("failed to start TCP listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	cfg := config{
		tcpPorts:    []int{port},
		udpPorts:    nil,
		timeout:     500 * time.Millisecond,
		retries:     0,
		concurrency: 1,
		rate:        0,
		serviceMap:  defaultServiceMap(),
	}
	results := runScan(cfg, &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]
	if res.State != "open" {
		t.Fatalf("expected TCP port to be open, got state %s (%s)", res.State, res.Reason)
	}
	if res.Attempts != 1 {
		t.Fatalf("expected a single attempt, got %d", res.Attempts)
	}
	if res.Latency < 0 {
		t.Fatalf("latency should be non-negative, got %v", res.Latency)
	}
}

func TestIntegrationUDPScan(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		if shouldSkipListen(err) {
			t.Skipf("skipping UDP integration test: %v", err)
		}
		t.Fatalf("failed to start UDP listener: %v", err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Bounce data back so the scanner treats the port as open.
			_, _ = conn.WriteToUDP(buf[:n], remote)
		}
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	cfg := config{
		tcpPorts:    nil,
		udpPorts:    []int{port},
		timeout:     500 * time.Millisecond,
		retries:     0,
		concurrency: 1,
		rate:        0,
		serviceMap:  defaultServiceMap(),
	}
	results := runScan(cfg, &net.IPAddr{IP: net.ParseIP("127.0.0.1")})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	res := results[0]
	if res.State != "open" {
		t.Fatalf("expected UDP port to be open, got state %s (%s)", res.State, res.Reason)
	}
	if res.Attempts != 1 {
		t.Fatalf("expected a single attempt, got %d", res.Attempts)
	}
	if res.Latency < 0 {
		t.Fatalf("latency should be non-negative, got %v", res.Latency)
	}
}

func shouldSkipListen(err error) bool {
	if errors.Is(err, syscall.EPERM) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.EPERM) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied") ||
		strings.Contains(strings.ToLower(err.Error()), "operation not permitted")
}
