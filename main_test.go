package main

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestMergePorts(t *testing.T) {
	input := "22,80-81,22,443"
	got, err := mergePorts(input, nil)
	if err != nil {
		t.Fatalf("mergePorts returned error: %v", err)
	}
	want := []int{22, 80, 81, 443}
	if len(got) != len(want) {
		t.Fatalf("expected %d ports, got %d", len(want), len(got))
	}
	for i, port := range want {
		if got[i] != port {
			t.Fatalf("expected port %d at index %d, got %d", port, i, got[i])
		}
	}
}

func TestMergePortsInvalid(t *testing.T) {
	if _, err := mergePorts("abc", nil); err == nil {
		t.Fatal("mergePorts should reject non-numeric values")
	}
	if _, err := mergePorts("-1", nil); err == nil {
		t.Fatal("mergePorts should reject out-of-range ports")
	}
	if _, err := mergePorts("10-5", nil); err != nil {
		t.Fatalf("mergePorts should tolerate reversed ranges: %v", err)
	}
}

func TestGuessService(t *testing.T) {
	services := defaultServiceMap()
	if got := guessService(22, services); got != "ssh" {
		t.Fatalf("expected ssh, got %s", got)
	}
	if got := guessService(9999, services); got != "-" {
		t.Fatalf("expected dash for unknown service, got %s", got)
	}
}

func TestLoadServiceOverrides(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/services.txt"
	data := []byte("8081=custom-http\n# comment line\n  99 = foo  \n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	overrides, err := loadServiceOverrides(path)
	if err != nil {
		t.Fatalf("loadServiceOverrides returned error: %v", err)
	}
	if overrides[8081] != "custom-http" {
		t.Fatalf("expected 8081 override, got %q", overrides[8081])
	}
	if overrides[99] != "foo" {
		t.Fatalf("expected 99 override, got %q", overrides[99])
	}

	badPath := dir + "/bad.txt"
	if err := os.WriteFile(badPath, []byte("oops"), 0o600); err != nil {
		t.Fatalf("failed to write bad override file: %v", err)
	}
	if _, err := loadServiceOverrides(badPath); err == nil {
		t.Fatal("expected loadServiceOverrides to fail on malformed line")
	}
}

func TestSortResults(t *testing.T) {
	results := []result{
		{Port: 53, Proto: "udp"},
		{Port: 80, Proto: "tcp"},
		{Port: 22, Proto: "tcp"},
	}
	sortResults(results)
	if results[0].Port != 22 || results[0].Proto != "tcp" {
		t.Fatalf("expected TCP 22 first, got %+v", results[0])
	}
	if results[1].Port != 80 || results[1].Proto != "tcp" {
		t.Fatalf("expected TCP 80 second, got %+v", results[1])
	}
	if results[2].Proto != "udp" {
		t.Fatalf("expected UDP entry last, got %+v", results[2])
	}
}

func TestResolveTargetNoDNS(t *testing.T) {
	ip := "192.0.2.1"
	addr, display, err := resolveTarget(ip, true)
	if err != nil {
		t.Fatalf("resolveTarget returned error: %v", err)
	}
	if addr.String() != ip {
		t.Fatalf("expected %s, got %s", ip, addr.String())
	}
	if display != ip {
		t.Fatalf("expected display %s, got %s", ip, display)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyTCPErrors(t *testing.T) {
	timeout := &net.OpError{Err: timeoutError{}}
	if state, _ := classifyTCPErr(timeout); state != "filtered" {
		t.Fatalf("expected filtered on timeout, got %s", state)
	}

	refused := &net.OpError{Err: syscall.ECONNREFUSED}
	if state, _ := classifyTCPErr(refused); state != "closed" {
		t.Fatalf("expected closed on ECONNREFUSED, got %s", state)
	}

	generic := errors.New("boom")
	if state, _ := classifyTCPErr(generic); state != "filtered" {
		t.Fatalf("expected filtered on generic error, got %s", state)
	}
}

func TestClassifyUDPErrors(t *testing.T) {
	refused := &net.OpError{Err: &os.SyscallError{Err: syscall.ECONNREFUSED}}
	if state, _ := classifyUDPErr(refused); state != "closed" {
		t.Fatalf("expected closed on ECONNREFUSED, got %s", state)
	}

	timeout := &net.OpError{Err: timeoutError{}}
	if state, _ := classifyUDPErr(timeout); state != "open|filtered" {
		t.Fatalf("expected open|filtered on timeout, got %s", state)
	}
}
