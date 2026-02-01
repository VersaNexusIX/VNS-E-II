# VNS-E-II Network Monitor

A network traffic monitoring tool written in V that detects anomalies and suspicious network behavior on Linux systems.

## Overview

VNS-E-II monitors active network connections and analyzes them based on multiple factors including process reputation, destination characteristics, and traffic patterns. It tracks hosts over time and identifies suspicious connections through a risk scoring system.

## Features

- Real-time connection monitoring via `ss` command
- Process-based risk multipliers for known safe applications
- Domain entropy analysis to detect algorithmically generated domains
- Private IP detection to filter internal traffic
- Host profiling and maturity tracking
- Bandwidth baseline establishment with EMA (Exponential Moving Average)
- Traffic spike detection
- JSON export of flagged connections

## Requirements

- Linux system with `/proc/net/dev` available
- `ss` command-line utility
- V language compiler (v0.4+)

## Building

```bash
v vns.v
```

This will produce an executable file.

## Usage

```bash
./vns
```

The monitor will run in a loop, displaying:
- Current bandwidth usage
- Baseline bandwidth calculation
- Number of tracked unique hosts
- Status information

Connections with risk scores of 35 or higher are logged to `vns_e_ii_log.json`.

## How It Works

### Risk Scoring

The tool calculates a risk score for each connection based on:

1. **New Destination**: First-time connection to an external host (20 points)
2. **Immature Host**: Host with less than 10 connections or established less than 5 minutes ago (10 points)
3. **Direct IP Connection**: Connecting directly to an IP without reverse DNS resolution (15 points)
4. **Domain Entropy**: High entropy in domain names may indicate algorithmic generation (up to 35 points)
5. **Suspicious Ports**: Connections to known suspicious ports (50 points)
6. **Rare Ports**: Connections to ports above 10000 (15 points)

Final score is multiplied by:
- Process multiplier (trusted apps: 0.6x, unknown: 1.5x, others: 1.0x)
- Traffic spike multiplier (1.3x when bandwidth anomaly detected)

### Risk Tiers

- CRITICAL: score >= 80
- HIGH: score >= 50
- MEDIUM: score >= 25
- LOW: score < 25

### Calibration

On startup, the tool enters a 5-second learning mode to establish a bandwidth baseline. No alerts are triggered during this period.

## Configuration

Safe processes (reduced risk multiplier):
```
firefox, chrome, brave, spotify, discord, slack, code, cursor, opera, telegram-desktop
```

Suspicious ports monitored:
```
4444, 1337, 666, 31337, 12345, 5555, 23, 2222, 9001, 8888
```

## Output Files

- `vns_e_ii_log.json`: JSON-formatted log of flagged connections

## Technical Details

### Structures

- `HostProfile`: Tracks connection count, first/last seen timestamps, and maturity status
- `TrafficLog`: Represents a single connection with risk assessment
- `SysStats`: Maintains bandwidth statistics and baseline
- `TrafficMemory`: Stores host profiles indexed by IP address
- `DNSCache`: Caches reverse DNS lookups

### Key Functions

- `get_system_bytes()`: Reads bandwidth from `/proc/net/dev`
- `get_connections()`: Parses active connections from `ss` output
- `analyze_domain_entropy()`: Calculates Shannon entropy of domain names
- `update_memory()`: Tracks and manages host profiles
- `calculate_process_multiplier()`: Determines risk adjustment based on process name

## Limitations

- Requires root or CAP_NET_ADMIN to read all connections
- DNS resolution via `getent` (may be slow on some systems)
- Designed for single-threaded monitoring loop
- No persistent storage between runs (except JSON log)

## License

Not specified
