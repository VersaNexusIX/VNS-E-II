# Security Considerations

## Privileges Required

VNS-E-II requires elevated privileges to function properly:

- Root access or `CAP_NET_ADMIN` capability to read all active connections via `ss`
- Read access to `/proc/net/dev` for bandwidth statistics
- Ability to execute `getent` for DNS resolution

Running without proper privileges will result in incomplete connection data and reduced visibility into network activity.

## Known Limitations

### DNS Resolution Performance

The tool performs synchronous DNS reverse lookups via `getent` for each new IP address encountered. In environments with slow or unreliable DNS, this may cause the monitoring loop to block temporarily. The DNS cache mitigates repeated lookups for known IPs.

### Process Identification

Process names are extracted from `ss` output and may not always accurately reflect the true origin of a connection. The tool relies on kernel-provided process information which can be spoofed in certain scenarios.

### Port Detection

The suspicious port list is static and based on historically common attack vectors. This is not exhaustive and serves only as a basic heuristic.

### Entropy Analysis

Domain entropy is calculated on the raw domain string. This may produce false positives for legitimate services with high-entropy names or false negatives for obfuscated domains using common character distributions.

### Baseline Calibration

The initial 5-second calibration window may not be representative if the system experiences unusual network activity during startup. The EMA baseline adapts over time but does not retroactively adjust historical comparisons.

## Data Handling

### JSON Log Files

Connection logs are appended to `vns_e_ii_log.json` without rotation or size limits. Over extended monitoring periods, this file may grow significantly. Consider implementing log rotation if deploying for long-term use.

### Sensitive Information

Exported logs contain:
- IP addresses (both internal and external)
- Process names
- Port numbers
- Reverse DNS hostnames

Restrict access to log files as they may reveal network topology and internal services.

### DNS Cache

The in-memory DNS cache is cleared on each program restart. Cached entries are not persisted.

### Host Profiling

Host profiles are stored in memory only and tracked per IP address. Long-running instances will accumulate profile data for all external hosts contacted.

## Risk Scoring Interpretation

The risk scoring system is designed to flag potentially anomalous connections, but high scores do not definitively indicate malicious activity. Consider the following when evaluating alerts:

- Legitimate services may connect to new destinations
- DNS-based services may use high-entropy subdomains
- Legitimate applications may use non-standard ports
- False positives increase in development/testing environments

Review context and process information when investigating alerts.

## Environment Assumptions

The tool assumes a standard Linux system with:
- Procfs mounted at `/proc`
- `ss` utility available in PATH
- `getent` utility for DNS resolution
- Standard network interface naming conventions

Behavior on alternative systems or custom kernel configurations is not tested.

## Safe Process List

The following processes receive reduced risk scoring:
- Browser applications: firefox, chrome, brave, opera
- Communication: discord, slack, telegram-desktop
- Development: code, cursor
- Media: spotify

Adding or removing processes from this list requires code modification and recompilation.

## Recommendations

1. Run as a dedicated service user if possible rather than root
2. Implement log rotation for long-term deployment
3. Regularly review and tune the risk thresholds based on your environment
4. Monitor system resources as DNS lookups can be expensive
5. Validate alerts with additional monitoring tools before taking action
6. Keep baseline and threshold values appropriate for your network's normal traffic patterns
