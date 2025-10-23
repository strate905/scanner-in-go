// Package main implements an educational network port scanner in Go.
// This scanner demonstrates TCP connect() and UDP scanning techniques,
// error handling, concurrent programming patterns, and network protocol behavior.
//
// Copyright (C) 2025 Strategos Network Scanner Project
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Scanner configuration constants that define default behavior.
// These values balance performance and reliability for educational use.
const (
	// defaultTimeout is how long we wait for a single port probe to respond.
	// 3 seconds gives most services time to respond without making scans too slow.
	defaultTimeout = 3 * time.Second

	// defaultRetries controls how many times we retry an unanswered probe.
	// Setting this to 1 means each port gets 2 total attempts (initial + 1 retry).
	defaultRetries = 1

	// defaultConcurrency limits how many simultaneous port probes we run.
	// 100 concurrent probes balances speed with system resource usage.
	defaultConcurrency = 100
)

var (
	// topTCPPorts contains the 25 most commonly open TCP ports based on Nmap's
	// nmap-services frequency data. This provides a good default scan set for
	// educational purposes without scanning all 65535 ports.
	topTCPPorts = []int{80, 443, 22, 21, 25, 23, 53, 110, 135, 139, 143, 445, 3389, 3306, 8080, 5900, 993, 995, 465, 587, 111, 2049, 1025, 1723, 554}

	// topUDPPorts contains the 5 most commonly open UDP ports.
	// UDP scanning is slower and less reliable than TCP, so we default to fewer ports.
	topUDPPorts = []int{53, 123, 161, 500, 1900}

	// baseServiceNames provides a best-effort service name guess based on IANA
	// port number registrations. These are standardized assignments, but the actual
	// service running on a port may differ (e.g., a web server on port 8080).
	baseServiceNames = map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		123:  "ntp",
		135:  "msrpc",
		137:  "netbios-ns",
		138:  "netbios-dgm",
		139:  "netbios-ssn",
		143:  "imap",
		161:  "snmp",
		443:  "https",
		445:  "microsoft-ds",
		465:  "smtps",
		500:  "isakmp",
		587:  "submission",
		993:  "imaps",
		995:  "pop3s",
		1025: "blackjack",
		1723: "pptp",
		1900: "ssdp",
		2049: "nfs",
		3306: "mysql",
		3389: "ms-wbt-server",
		5900: "vnc",
		8080: "http-alt",
	}
)

// defaultServiceMap creates a new map copy from baseServiceNames.
// We create a copy rather than using the global directly to allow
// users to safely modify it with custom service name overrides.
func defaultServiceMap() map[int]string {
	out := make(map[int]string, len(baseServiceNames))
	for port, name := range baseServiceNames {
		out[port] = name
	}
	return out
}

// config holds all user-configurable scanner settings.
// This struct is populated from command-line flags and passed to scanning functions.
type config struct {
	target      string            // Target hostname or IP address to scan
	tcpPorts    []int             // List of TCP ports to probe
	udpPorts    []int             // List of UDP ports to probe
	timeout     time.Duration     // Per-probe timeout
	retries     int               // Number of retry attempts for unanswered probes
	concurrency int               // Maximum simultaneous probes
	rate        float64           // Optional rate limit in packets/second (0 = no limit)
	noDNS       bool              // Skip DNS resolution, use target as literal IP
	jsonOutput  bool              // Output format: JSON if true, Markdown if false
	serviceMap  map[int]string    // Port-to-service-name mappings
}

// job represents a single port scanning task to be processed by a worker.
// Jobs are sent through a channel to distribute work across goroutines.
type job struct {
	port  int    // Port number to scan
	proto string // Protocol: "tcp" or "udp"
}

// result contains the outcome of scanning a single port.
// This struct is JSON-serializable for machine-readable output.
type result struct {
	Port     int           `json:"port"`     // Port number that was scanned
	Proto    string        `json:"proto"`    // Protocol used: "tcp" or "udp"
	State    string        `json:"state"`    // Port state: "open", "closed", "filtered", or "open|filtered"
	Service  string        `json:"service"`  // Guessed service name based on port number
	Reason   string        `json:"reason"`   // Human-readable explanation of why we determined this state
	Attempts int           `json:"attempts"` // Number of probe attempts made (including retries)
	Latency  time.Duration `json:"latency"`  // Total time spent probing this port
}

// main orchestrates the scanning workflow:
// 1. Parse command-line flags into a config struct
// 2. Resolve the target hostname to an IP address
// 3. Run the port scan concurrently
// 4. Sort and output the results
func main() {
	cfg := parseFlags()

	// Default to scanning localhost if no target is specified.
	// This makes the tool safe for initial experimentation.
	targetHost := cfg.target
	if targetHost == "" {
		targetHost = "127.0.0.1"
	}

	// resolveTarget performs DNS lookup (unless --no-dns) and returns both
	// the IP address to scan and a display string for output.
	resolvedAddr, displayTarget, err := resolveTarget(targetHost, cfg.noDNS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve target: %v\n", err)
		os.Exit(1)
	}

	// runScan performs the actual port scanning using concurrent workers.
	results := runScan(cfg, resolvedAddr)

	// Sort results by protocol first (TCP before UDP), then by port number.
	// This produces predictable, readable output.
	sortResults(results)

	// Output results in the requested format.
	if cfg.jsonOutput {
		if err := writeJSON(displayTarget, results); err != nil {
			fmt.Fprintf(os.Stderr, "json output: %v\n", err)
			os.Exit(1)
		}
		return
	}

	writeMarkdown(displayTarget, results)
}

// parseFlags processes command-line arguments and returns a populated config struct.
// It validates input ranges and provides helpful error messages for educational clarity.
func parseFlags() config {
	var (
		tcpList = flag.String("tcp", "", "Comma separated TCP ports or ranges (e.g. 22,80-90). Defaults to top 25 TCP ports.")
		udpList = flag.String("udp", "", "Comma separated UDP ports or ranges (e.g. 53,161). Defaults to top 5 UDP ports.")
		timeout = flag.Float64("timeout", defaultTimeout.Seconds(), "Per-probe timeout in seconds.")
		retries = flag.Int("retries", defaultRetries, "Number of retries for unanswered probes.")
		concur  = flag.Int("concurrency", defaultConcurrency, "Maximum simultaneous probes across all protocols.")
		rate    = flag.Float64("rate", 0, "Optional rate limit in packets per second (0 disables).")
		noDNS   = flag.Bool("no-dns", false, "Skip DNS resolution and use the provided target literally.")
		jsonOut = flag.Bool("json", false, "Emit results as JSON instead of Markdown.")
		svcFile = flag.String("service-map", "", "Optional file containing custom service guesses as port=name per line.")
	)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Educational TCP/UDP scanner.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] <target>\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), "\nUDP note: UDP rarely answers; lack of response means open|filtered, while ECONNREFUSED implies an ICMP Port Unreachable (closed).")
	}

	flag.Parse()

	// Parse the user-provided port lists (or use defaults if not specified).
	// mergePorts handles comma-separated values, ranges (e.g., 80-90), and deduplication.
	tcpPorts, err := mergePorts(*tcpList, topTCPPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse --tcp: %v\n", err)
		os.Exit(1)
	}
	udpPorts, err := mergePorts(*udpList, topUDPPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse --udp: %v\n", err)
		os.Exit(1)
	}

	// Validate numeric parameters to catch configuration errors early.
	if *concur <= 0 {
		fmt.Fprintf(os.Stderr, "--concurrency must be >0\n")
		os.Exit(1)
	}
	if *retries < 0 {
		fmt.Fprintf(os.Stderr, "--retries must be >=0\n")
		os.Exit(1)
	}
	if *timeout <= 0 {
		fmt.Fprintf(os.Stderr, "--timeout must be >0\n")
		os.Exit(1)
	}

	// Start with default service names, then apply any user-provided overrides.
	serviceMap := defaultServiceMap()
	if strings.TrimSpace(*svcFile) != "" {
		overrides, err := loadServiceOverrides(*svcFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load --service-map: %v\n", err)
			os.Exit(1)
		}
		// Merge overrides into the default map (user values take precedence).
		for port, name := range overrides {
			serviceMap[port] = name
		}
	}

	return config{
		target:      firstArg(),
		tcpPorts:    tcpPorts,
		udpPorts:    udpPorts,
		timeout:     time.Duration(*timeout * float64(time.Second)),
		retries:     *retries,
		concurrency: *concur,
		rate:        *rate,
		noDNS:       *noDNS,
		jsonOutput:  *jsonOut,
		serviceMap:  serviceMap,
	}
}

// firstArg extracts the first positional argument (the target) after flag parsing.
// Returns empty string if no positional arguments were provided.
func firstArg() string {
	if flag.NArg() == 0 {
		return ""
	}
	return flag.Arg(0)
}

// mergePorts converts a user-provided port specification into a sorted, deduplicated slice.
// Input format: comma-separated ports and ranges (e.g., "22,80-90,443")
// If input is empty, returns a copy of the defaults slice.
// Ranges with reversed bounds (e.g., "90-80") are automatically corrected.
func mergePorts(input string, defaults []int) ([]int, error) {
	if strings.TrimSpace(input) == "" {
		// Return a copy of defaults to avoid shared slice issues.
		return append([]int(nil), defaults...), nil
	}

	// Use a map to track which ports we've already added (deduplication).
	seen := make(map[int]struct{})
	var ports []int
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Handle port ranges like "80-90".
		if strings.Contains(part, "-") {
			limits := strings.Split(part, "-")
			if len(limits) != 2 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(limits[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start in %q: %w", part, err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(limits[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end in %q: %w", part, err)
			}
			// Automatically correct reversed ranges (e.g., "90-80" becomes "80-90").
			if start > end {
				start, end = end, start
			}
			// Expand the range into individual ports.
			for p := start; p <= end; p++ {
				if err := validatePort(p); err != nil {
					return nil, err
				}
				// Skip if we've already seen this port (deduplication).
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
			continue
		}
		// Handle individual port numbers.
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		if err := validatePort(p); err != nil {
			return nil, err
		}
		// Skip duplicates.
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	// Sort ports numerically for predictable output.
	sort.Ints(ports)
	return ports, nil
}

// validatePort checks whether a port number is in the valid range (1-65535).
// Port 0 is reserved and cannot be scanned; ports above 65535 don't exist.
func validatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d out of range", p)
	}
	return nil
}

// loadServiceOverrides reads a service mapping file in "port=name" format.
// Lines starting with '#' are treated as comments and ignored.
// This allows users to customize service names for their environment.
func loadServiceOverrides(path string) (map[int]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	overrides := make(map[int]string)
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments.
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		// Split on the first '=' to allow service names with '=' in them.
		parts := strings.SplitN(text, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s:%d: expected port=name", path, line)
		}
		portVal := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])
		port, err := strconv.Atoi(portVal)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid port %q: %w", path, line, portVal, err)
		}
		if err := validatePort(port); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if name == "" {
			return nil, fmt.Errorf("%s:%d: service name cannot be empty", path, line)
		}
		overrides[port] = name
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return overrides, nil
}

// resolveTarget converts a hostname or IP string into a net.IPAddr for scanning.
// When noDNS is false, it performs DNS lookup and prefers IPv4 addresses.
// Returns both the resolved IP and a human-readable display string.
func resolveTarget(target string, noDNS bool) (*net.IPAddr, string, error) {
	if noDNS {
		// --no-dns mode: treat target as a literal IP address.
		ip := net.ParseIP(target)
		if ip == nil {
			return nil, "", fmt.Errorf("invalid IP address %q with --no-dns", target)
		}
		return &net.IPAddr{IP: ip}, ip.String(), nil
	}

	// Perform DNS lookup. This works for both hostnames and IP strings.
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, "", err
	}
	if len(ips) == 0 {
		return nil, "", fmt.Errorf("no IPs returned for %q", target)
	}

	// Prefer IPv4 for scanning (more common and simpler for learning).
	ip := pickPreferredIP(ips)
	display := fmt.Sprintf("%s (%s)", target, ip.String())
	return &net.IPAddr{IP: ip}, display, nil
}

// pickPreferredIP selects an IPv4 address if available, otherwise returns the first IP.
// IPv4 addresses are more common in typical scanning scenarios and easier to understand.
func pickPreferredIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		// To4() returns non-nil only for valid IPv4 addresses.
		if ip.To4() != nil {
			return ip
		}
	}
	// If no IPv4 found, use the first IP (likely IPv6).
	return ips[0]
}

// runScan orchestrates concurrent port scanning using the worker pool pattern.
// This is a classic Go concurrency idiom:
// 1. Create buffered channels for jobs and results
// 2. Spawn N worker goroutines that process jobs concurrently
// 3. A producer goroutine feeds jobs into the channel
// 4. Main goroutine collects results until all workers finish
func runScan(cfg config, target *net.IPAddr) []result {
	jobs := make(chan job)
	resultsCh := make(chan result)

	// Spawn worker goroutines equal to the concurrency limit.
	// Each worker will process jobs from the channel until it's closed.
	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(cfg, target, jobs, resultsCh)
		}()
	}

	// Producer goroutine: feed all port/protocol combinations into the jobs channel.
	go func() {
		defer close(jobs) // Signal workers that no more jobs are coming.
		emitJobs(cfg, jobs)
	}()

	// Closer goroutine: wait for all workers to finish, then close results channel.
	go func() {
		wg.Wait()
		close(resultsCh) // Signal main goroutine that all results are in.
	}()

	// Collect all results from the channel.
	// This blocks until resultsCh is closed (when all workers finish).
	var out []result
	for res := range resultsCh {
		out = append(out, res)
	}
	return out
}

// emitJobs feeds scanning jobs into the jobs channel.
// If rate limiting is configured, it uses a time.Ticker to throttle packet dispatch.
func emitJobs(cfg config, jobs chan<- job) {
	var (
		rateTicker *time.Ticker
		throttle   <-chan time.Time
		sent       int
	)

	// Set up rate limiting if requested.
	// Rate is specified in packets per second.
	if cfg.rate > 0 {
		// Calculate the interval between packets: 1 second / packets_per_second.
		interval := time.Duration(float64(time.Second) / cfg.rate)
		// Clamp minimum interval to 1ms to avoid spinning too fast on high rates.
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		rateTicker = time.NewTicker(interval)
		defer rateTicker.Stop()
		throttle = rateTicker.C
	}

	// Helper function to send a job, applying rate limiting if configured.
	send := func(j job) {
		// Wait for the ticker if we're rate-limiting and this isn't the first packet.
		if throttle != nil && sent > 0 {
			<-throttle // Block until next tick.
		}
		sent++
		jobs <- j
	}

	// Emit all TCP port jobs first, then UDP.
	for _, port := range cfg.tcpPorts {
		send(job{port: port, proto: "tcp"})
	}
	for _, port := range cfg.udpPorts {
		send(job{port: port, proto: "udp"})
	}
}

// worker processes jobs from the jobs channel and sends results to the results channel.
// Each worker runs in its own goroutine, enabling concurrent scanning.
func worker(cfg config, target *net.IPAddr, jobs <-chan job, results chan<- result) {
	for j := range jobs {
		switch j.proto {
		case "tcp":
			results <- scanTCP(cfg, target, j.port)
		case "udp":
			results <- scanUDP(cfg, target, j.port)
		}
	}
}

// scanTCP performs a TCP connect() scan on a single port.
// This is an "unprivileged" technique that works without raw socket access.
// The three-way handshake behavior:
// - If connect() succeeds → port is OPEN
// - If connect() gets ECONNREFUSED → port is CLOSED (RST received)
// - If connect() times out → port is FILTERED (firewall dropping packets)
func scanTCP(cfg config, target *net.IPAddr, port int) result {
	address := net.JoinHostPort(target.String(), strconv.Itoa(port))
	reason := ""
	state := "filtered"
	start := time.Now()
	attempts := 0

	// Try up to (retries + 1) times.
	for attempt := 0; attempt <= cfg.retries; attempt++ {
		attempts = attempt + 1
		// DialTimeout attempts a TCP three-way handshake.
		conn, err := net.DialTimeout("tcp", address, cfg.timeout)
		if err == nil {
			// Success! The handshake completed, so the port is open.
			_ = conn.Close()
			return result{
				Port:     port,
				Proto:    "tcp",
				State:    "open",
				Service:  guessService(port, cfg.serviceMap),
				Reason:   "connect() succeeded",
				Attempts: attempts,
				Latency:  time.Since(start),
			}
		}
		// Classify the error to determine if we should retry.
		state, reason = classifyTCPErr(err)
		// If we got a definitive answer (closed/open), don't retry.
		if state == "closed" || state == "open" {
			break
		}
		// Otherwise (filtered/timeout), continue retrying.
	}

	return result{
		Port:     port,
		Proto:    "tcp",
		State:    state,
		Service:  guessService(port, cfg.serviceMap),
		Reason:   reason,
		Attempts: attempts,
		Latency:  time.Since(start),
	}
}

// classifyTCPErr interprets TCP connection errors to determine port state.
// Go's net package wraps system errors in net.OpError, so we unwrap to check the cause.
func classifyTCPErr(err error) (string, string) {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		// Check if the error was a timeout (no response within deadline).
		if opErr.Timeout() {
			return "filtered", "timeout during connect()"
		}
		// Check for ECONNREFUSED, which means we got a TCP RST packet.
		// This indicates the port is closed (nothing is listening).
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
			if sysErr.Err == syscall.ECONNREFUSED {
				return "closed", "connect() refused"
			}
		}
		// Also check using errors.Is for unwrapped ECONNREFUSED.
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return "closed", "connect() refused"
		}
	}
	// For any other error, assume the port is filtered (firewalled).
	return "filtered", err.Error()
}

// scanUDP performs a UDP port scan.
// UDP scanning is inherently unreliable because UDP is connectionless.
// Without receiving a response, we cannot distinguish between:
// - Port OPEN (service ignoring our probe)
// - Port FILTERED (firewall dropping packets)
// The only definitive signal is ICMP Port Unreachable (type 3, code 3),
// which the OS reports as ECONNREFUSED → port is CLOSED.
func scanUDP(cfg config, target *net.IPAddr, port int) result {
	address := net.JoinHostPort(target.String(), strconv.Itoa(port))
	state := "open|filtered"
	reason := "no reply"
	start := time.Now()
	attempts := 0

	for attempt := 0; attempt <= cfg.retries; attempt++ {
		attempts = attempt + 1
		// "Dial" a UDP connection (this doesn't send anything yet).
		conn, err := net.DialTimeout("udp", address, cfg.timeout)
		if err != nil {
			state, reason = classifyUDPErr(err)
			if state == "closed" {
				break
			}
			continue
		}

		// Send a minimal probe (single null byte).
		// This is enough to trigger an ICMP Port Unreachable if the port is closed.
		payload := []byte{0x00}
		_ = conn.SetDeadline(time.Now().Add(cfg.timeout))

		if _, err := conn.Write(payload); err != nil {
			state, reason = classifyUDPErr(err)
			_ = conn.Close()
			if state == "closed" {
				break
			}
			continue
		}

		// Try to read a response.
		buffer := make([]byte, 512)
		n, err := conn.Read(buffer)
		_ = conn.Close()
		if err != nil {
			// TRICKY: Go surfaces ICMP Port Unreachable as ECONNREFUSED on Read().
			// This is the operating system telling us the remote host sent back
			// "ICMP type 3 code 3" in response to our UDP packet.
			state, reason = classifyUDPErr(err)
			if state == "closed" {
				break
			}
			continue
		}
		// We got data back! The port is definitely open.
		state = "open"
		reason = fmt.Sprintf("received %d bytes", n)
		break
	}

	return result{
		Port:     port,
		Proto:    "udp",
		State:    state,
		Service:  guessService(port, cfg.serviceMap),
		Reason:   reason,
		Attempts: attempts,
		Latency:  time.Since(start),
	}
}

// classifyUDPErr interprets UDP operation errors.
// ECONNREFUSED is the key signal: it means the kernel received an
// ICMP Port Unreachable message, indicating the port is closed.
func classifyUDPErr(err error) (string, string) {
	var opErr *net.OpError

	if errors.As(err, &opErr) {
		// Timeout means no response - could be open or filtered.
		if opErr.Timeout() {
			return "open|filtered", "no reply (timeout)"
		}
		// ECONNREFUSED indicates ICMP Port Unreachable was received.
		// This is the ONLY way to definitively identify a closed UDP port.
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) && sysErr.Err == syscall.ECONNREFUSED {
			return "closed", "ICMP Port Unreachable (ECONNREFUSED)"
		}
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return "closed", "ICMP Port Unreachable (ECONNREFUSED)"
		}
		return "open|filtered", opErr.Err.Error()
	}
	return "open|filtered", err.Error()
}

// guessService looks up a service name for the given port.
// Returns "-" if no mapping exists.
func guessService(port int, services map[int]string) string {
	if name, ok := services[port]; ok {
		return name
	}
	return "-"
}

// sortResults orders scan results for consistent output.
// Primary sort: protocol (TCP before UDP alphabetically)
// Secondary sort: port number (ascending)
func sortResults(results []result) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Proto == results[j].Proto {
			return results[i].Port < results[j].Port
		}
		return results[i].Proto < results[j].Proto
	})
}

// writeJSON outputs scan results in JSON format to stdout.
// The output includes the target and an array of port scan results.
func writeJSON(target string, results []result) error {
	output := struct {
		Target  string   `json:"target"`
		Results []result `json:"results"`
	}{
		Target:  target,
		Results: results,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ") // Pretty-print with 2-space indentation.
	return enc.Encode(output)
}

// writeMarkdown outputs scan results as a formatted Markdown table to stdout.
// This is the default human-readable output format.
func writeMarkdown(target string, results []result) {
	fmt.Printf("# Target: %s\n\n", target)
	fmt.Println("| Port | Proto | State | Attempts | Latency | Service | Reason |")
	fmt.Println("|-----:|:-----:|:------|:--------:|:--------|:--------|:-------|")
	for _, r := range results {
		fmt.Printf("| %4d |  %3s  | %-12s | %8d | %-8s | %-7s | %s |\n",
			r.Port,
			strings.ToUpper(r.Proto),
			r.State,
			r.Attempts,
			formatDuration(r.Latency),
			r.Service,
			r.Reason)
	}
}

// formatDuration converts a time.Duration to a human-readable string.
// Rounds to microseconds so fast localhost scans show meaningful latency.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	// Round to microseconds for better precision on fast scans.
	rounded := d.Round(time.Microsecond)
	if rounded == 0 {
		return "<1us"
	}
	return rounded.String()
}
