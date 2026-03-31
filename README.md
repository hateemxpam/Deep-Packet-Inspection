# Deep Packet Inspection Engine (Offline PCAP, Multithreaded)

A C++17 Deep Packet Inspection (DPI) engine that reads packets from PCAP files, classifies traffic using protocol parsing + TLS SNI extraction, applies block rules, and writes filtered output PCAP.

Current implementation is multithreaded (v2) with:
- flow-affinity worker routing
- per-worker flow tables
- thread-safe rule checks
- optional output PCAP writing
- benchmark and worker statistics

## What This Project Does

Input:
- A PCAP file captured from Wireshark (offline)
- A rules file (block by IP, app, or domain substring)

Processing:
- Parse Ethernet/IPv4/TCP/UDP headers
- Build flow key (five-tuple)
- Extract SNI from TLS ClientHello (port 443)
- Classify app (Google, YouTube, GitHub, etc.)
- Apply rules and decide forward/drop

Output:
- Optional filtered PCAP with only forwarded packets
- Console benchmark + throughput + per-worker stats

## Why This Is Useful

- Demonstrates systems programming in C++
- Covers networking internals and binary parsing
- Shows practical multithreading design
- Produces measurable performance metrics

## High-Level Architecture

```text
								 +-----------------------------+
								 | Main Thread                |
								 | - Parse CLI                |
								 | - Load rules               |
								 | - Start hot-reload watcher |
								 | - Run MTEngine             |
								 +-------------+---------------+
															 |
															 v
									 +-------------------------+
									 | Reader (inside MTEngine)|
									 | reads PCAP packets      |
									 +-----------+-------------+
															 |
										 hash(flow) % workers
															 |
							+----------------+----------------+
							|                                 |
							v                                 v
			+---------------+                 +---------------+
			| Worker 0      |   ...           | Worker N-1    |
			| - parse       |                 | - parse       |
			| - classify    |                 | - classify    |
			| - block check |                 | - block check |
			+-------+-------+                 +-------+-------+
							|                                 |
							+----------------+----------------+
															 |
															 v
										+-----------------------+
										| Shared Output Queue   |
										+-----------+-----------+
																|
																v
										+-----------------------+
										| Writer Thread         |
										| writes forwarded PCAP |
										+-----------------------+
```

## Packet Journey (Step-by-Step)

1. Reader gets next packet from PCAP.
2. Reader parses enough headers to select worker via flow-affinity hash.
3. Packet is pushed to that worker queue.
4. Worker parses packet fully (Ethernet/IP/TCP/UDP).
5. Worker gets/updates flow state in its private flow table.
6. For TLS ClientHello traffic, worker buffers handshake bytes and extracts SNI.
7. Worker classifies app from SNI/domain pattern.
8. Worker checks rules:
	 - BLOCK_IP
	 - BLOCK_APP
	 - BLOCK_DOMAIN (substring match)
9. If allowed, packet goes to output queue; else it is dropped.
10. Writer thread drains output queue to output PCAP.
11. Engine prints aggregate and per-worker statistics.

## Project Structure

```text
Deep Packet Inspection/
├── CMakeLists.txt
├── README.md
├── rules/
│   └── rules.txt
├── data/
│   ├── capture.pcap
│   └── output.pcap
├── include/
│   ├── types.h              # Core data models (RawPacket, ParsedPacket, Flow, AppType)
│   ├── pcap_reader.h        # Offline PCAP reader interface
│   ├── packet_parser.h      # Packet parser interface
│   ├── sni_extractor.h      # TLS SNI extraction interface
│   ├── rule_manager.h       # Thread-safe rules engine
│   ├── thread_safe_queue.h  # Bounded producer/consumer queue
│   ├── worker.h             # Worker thread logic + per-worker stats
│   ├── mt_engine.h          # Multithreaded orchestrator
│   ├── hot_reload.h         # Rules file watcher
│   ├── flow_tracker.h       # Legacy/utility flow tracker
│   └── reporter.h           # Reporting utilities
└── src/
		├── main.cpp             # CLI, banner, hot-reload startup, report printing
		├── pcap_reader.cpp      # PCAP global/packet header reading
		├── packet_parser.cpp    # Ethernet/IPv4/TCP/UDP parsing
		├── sni_extractor.cpp    # TLS ClientHello SNI extraction
		├── rule_manager.cpp     # Rule loading and block checks
		├── worker.cpp           # Packet processing pipeline per worker
		├── mt_engine.cpp        # Reader routing, workers, writer, throughput metrics
		├── hot_reload.cpp       # Polling-based rules reload watcher
		├── types.cpp            # Hashing, app mapping, label normalization helpers
		├── flow_tracker.cpp     # Legacy/utility flow tracker impl
		└── reporter.cpp         # Additional report formatter
```

## Rules Format

Rules file path defaults to `rules/rules.txt`.

Supported commands:
- `BLOCK_IP <ipv4>`
- `BLOCK_APP <AppName>`
- `BLOCK_DOMAIN <substring>`

Example:

```text
BLOCK_APP YouTube
BLOCK_DOMAIN facebook
# BLOCK_IP 192.168.1.50
```

`BLOCK_DOMAIN` is substring-based and case-insensitive.

## Build and Run

## Prerequisites

- CMake 3.15+
- C++17 compiler
- On Windows (this repo setup): MinGW (MSYS2 UCRT64)

## Configure and build

From project root:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
```

If already configured, rebuild only:

```powershell
Set-Location build
cmake --build .
```

## Run (from project root)

```powershell
.\build\dpi_engine.exe .\data\capture.pcap .\data\output.pcap --rules .\rules\rules.txt --workers 2
```

## Run (from build folder)

```powershell
.\dpi_engine.exe ..\data\capture.pcap ..\data\output.pcap --rules ..\rules\rules.txt --workers 2
```

## CLI Usage

```text
dpi_engine <input.pcap> [output.pcap] [--rules <path>] [--workers N]
```

- `output.pcap` optional: if omitted, engine runs monitor-only (no output file).
- `--workers N`: bounded in code to [1, 16].

## Example Output (Abbreviated)

```text
============================================================
	DPI ENGINE v2.0 - Multithreaded
============================================================
	Workers : 2 thread(s)

[Engine] Starting 2 worker thread(s)...
[Engine] Reader done. Waiting for workers...

============================================================
	BENCHMARK RESULTS
============================================================
	Processing Time  : 0.120 seconds
	Throughput       : 15000 packets/sec
	Throughput       : 120.30 Mbps

============================================================
	PROCESSING REPORT
============================================================
	Forwarded      : 1827
	Dropped        : 11

	WORKER THREAD BREAKDOWN
	Worker #0 ...
	Worker #1 ...
```

## Key Design Decisions and Insights

1. Offline-first architecture
- Keeps the project deterministic and easy to test/replay.

2. Flow-affinity routing
- All packets in the same flow map to the same worker.
- Avoids shared-flow locks and reduces contention.

3. Per-worker flow state
- Each worker owns its flow table.
- Simpler concurrency model and better cache locality.

4. Thread-safe rule manager
- Rules are protected by mutex for concurrent reads/reloads.

5. Hot rule reload
- Rules file watcher reloads config while engine is running.

6. Throughput instrumentation
- Reports packets/sec and Mbps for performance comparison.

## Current Limitations

- IPv4-focused parsing path (no full IPv6 DPI path yet).
- SNI extraction only from TLS ClientHello payload path.
- No full TCP stream reassembly beyond initial handshake buffering.
- Rule language is intentionally simple (no regex priorities/actions).
- `tests/` is currently empty (manual runs are primary validation).

## Suggested Next Improvements

1. Add unit tests for parser bounds and SNI edge cases.
2. Add integration tests with fixed sample PCAP fixtures.
3. Add structured JSON report export for dashboards.
4. Add richer rule actions (allowlist, throttle, priority).
5. Add improved domain normalization/public-suffix handling.
6. Add benchmark script to compare worker counts automatically.

## Safety and Ethics Note

This project is for educational and defensive traffic analysis in controlled environments. Only inspect traffic you own or are authorized to analyze.