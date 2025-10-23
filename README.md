# Educational Network Scanner (Go)

This project implements a compact but faithful TCP/UDP port scanner aimed at learning how real-world scanners behave. It sticks to unprivileged techniques so you can read the complete source and run it anywhere without special permissions.

## Features

- Defaults to the top 25 TCP and top 5 UDP ports derived from Nmap frequency data.
- TCP `connect()` scans mirror what tools fall back to when raw sockets are unavailable.
- UDP probes classify ICMP Port Unreachable as `closed` and treat silence as `open|filtered`, matching the nuance of real scanners.
- Markdown table output by default with optional `--json`, now including per-port attempts and latency.
- Tunable concurrency, per-probe timeout, retry count, and optional packet rate limiting.
- Optional DNS resolution to display both the supplied hostname and resolved IP address.

## Installation

```bash
go build -o scanner
```

If you are in a restricted environment, you may need to set `CGO_ENABLED=0` and/or `GOCACHE` to a writable directory, e.g.

```bash
CGO_ENABLED=0 GOCACHE=$(pwd)/.gocache go build -o scanner
```

## Usage

```
scanner [--tcp PORTS] [--udp PORTS] [--timeout SECONDS] [--retries N] \
        [--concurrency N] [--rate PPS] [--no-dns] [--json] <target>
```

- `PORTS` accepts comma-separated values and ranges (`22,80-90`).
- `--timeout` applies to each probe attempt (default 3s).
- `--retries` resends unanswered probes (default 1, total attempts = retries + 1).
- `--concurrency` bounds how many probes run at once (default 100).
- `--rate` limits packet launches per second (fractional values allowed).
- When `<target>` is omitted, the scanner defaults to `127.0.0.1`.
- `--no-dns` bypasses hostname resolution and requires a literal IP.
- `--json` emits machine-readable output.
- `--service-map` points at a `port=name` file to override the built-in guesses.

### UDP Behavior Reminder

UDP does not have a handshake, so scanners infer state:

- ICMP Type 3 Code 3 (reported as `ECONNREFUSED`) ⇒ `closed`.
- No reply by the timeout ⇒ `open|filtered` (we cannot know which).
- Actual UDP payload responses ⇒ `open`.

The help output also summarizes this nuance for quick reference.

## Examples

```bash
# Scan the defaults against localhost
scanner

# Scan a specific host with custom TCP ports and JSON output
scanner --tcp 22,80,443 --json example.com

# Aggressive UDP scan with higher concurrency but a 200 packet/s rate limit
scanner --udp 53,123,161 --concurrency 200 --rate 200 target-host
```

## Testing

```bash
go test ./...
```

If you need to avoid CGO in your environment, run `CGO_ENABLED=0 go test ./...`.

## Custom Service Names

Create a text file with one override per line:

```
8443=https-alt
31337=elite
```

Run with:

```bash
scanner --service-map overrides.txt target-host
```

Overrides replace the defaults for matched ports; other entries fall back to the built-in guesses sourced from IANA registrations.

## Learning Notes

This scanner is designed as an educational tool with extensive inline documentation. Key learning topics covered in `main.go`:

### Go Concurrency Patterns
- **Worker pool pattern** (`runScan`): demonstrates channel-based job distribution across goroutines
- **WaitGroup usage**: proper synchronization of concurrent workers
- **Channel lifecycle**: coordinating producer, workers, and collector goroutines

### Network Programming
- **TCP connect() scanning** (`scanTCP`): unprivileged three-way handshake probing
- **UDP scanning challenges** (`scanUDP`): connectionless protocol behavior and state inference
- **Error classification**: unwrapping Go's net.OpError to identify specific syscall errors
- **ICMP handling**: how ICMP Port Unreachable surfaces as ECONNREFUSED in Go

### Best Practices
- **Structured error handling**: context-preserving error messages with error wrapping
- **Input validation**: port range checking and user input sanitization
- **Rate limiting**: time.Ticker-based packet rate control to avoid network flooding
- **Timeout configuration**: per-probe deadlines for responsive scanning

Each tricky section includes detailed comments explaining the "why" behind implementation choices, making the code suitable for self-study or classroom use.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
