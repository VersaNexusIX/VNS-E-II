import os
import time
import math
import json

struct HostProfile {
mut:
	count      int
	first_seen i64
	last_seen  i64
	is_mature  bool
}

struct TrafficMemory {
mut:
	hosts map[string]HostProfile
}

struct TrafficLog {
	timestamp     string
	process       string
	target_host   string
	target_ip     string
	port          int
	behavior_note string
	raw_entropy   f64
	proc_mult     f64
mut:
	risk_score int
	risk_tier  string
	tags       []string
}

struct SysStats {
mut:
	prev_bytes   u64
	ema_baseline f64
	accumulated  u64
	calibration  int
	last_checked i64
}

struct DNSCache {
mut:
	entries map[string]string
}

const safe_processes = ['firefox', 'chrome', 'brave', 'spotify', 'discord', 'slack', 'code', 'cursor', 'opera', 'telegram-desktop']

const suspicious_ports = [4444, 1337, 666, 31337, 12345, 5555, 23, 2222, 9001, 8888]

const pink = '\033[38;5;213m'
const cyan = '\033[38;5;159m'
const red = '\033[38;5;203m'
const yellow = '\033[38;5;226m'
const purple = '\033[38;5;141m'
const white = '\033[38;5;231m'
const grey = '\033[38;5;240m'
const reset = '\033[0m'
const bold = '\033[1m'

fn get_system_bytes() u64 {
	data := os.read_file('/proc/net/dev') or { return 0 }
	lines := data.split('\n')
	mut total := u64(0)
	for line in lines {
		if line.contains(':') && !line.contains('lo:') {
			parts := line.split_any(': \t')
			mut fields := []string{}
			for p in parts {
				if p.len > 0 {
					fields << p
				}
			}
			if fields.len >= 10 {
				total += fields[1].u64() + fields[9].u64()
			}
		}
	}
	return total
}

fn resolve_host_linux(ip string) string {
	res := os.execute('getent hosts ${ip}')
	if res.exit_code == 0 && res.output.len > 0 {
		parts := res.output.trim_space().split_any(' \t')
		if parts.len >= 2 {
			return parts[1]
		}
	}
	return ip
}

fn resolve_host_safe(mut cache DNSCache, ip string) string {
	if ip in cache.entries {
		return cache.entries[ip]
	}
	host := resolve_host_linux(ip)
	cache.entries[ip] = host
	return host
}

fn is_private_ip(ip string) bool {
	if ip.starts_with('192.168.') || ip.starts_with('10.') || ip == '127.0.0.1' {
		return true
	}
	if ip.starts_with('172.') {
		parts := ip.split('.')
		if parts.len >= 2 {
			octet := parts[1].int()
			if octet >= 16 && octet <= 31 {
				return true
			}
		}
	}
	return false
}

fn extract_process_safe(line string) string {
	marker := 'users:(("'
	start_idx := line.index(marker) or { return 'unknown' }
	sub := line[start_idx + marker.len..]
	end_idx := sub.index('"') or { return 'unknown' }
	return sub[..end_idx]
}

fn analyze_domain_entropy(domain string, is_ip bool) (f64, int, []string) {
	if domain == '' || is_ip {
		return 0.0, 0, []string{}
	}

	mut freqs := map[u8]f64{}
	len := f64(domain.len)
	for i in 0 .. domain.len {
		freqs[domain[i]]++
	}

	mut entropy := 0.0
	for _, count in freqs {
		p := count / len
		entropy -= p * math.log2(p)
	}

	mut score := 0
	mut tags := []string{}

	if entropy > 4.3 {
		score += 35
		tags << 'HIGH_ENTROPY'
	}

	mut nums := 0
	for i in 0 .. domain.len {
		if domain[i] >= 48 && domain[i] <= 57 {
			nums++
		}
	}
	if (f64(nums) / len) > 0.5 {
		score += 20
		tags << 'NUMERIC_HEAVY'
	}

	return entropy, score, tags
}

fn update_memory(mut memory TrafficMemory, ip string) (bool, bool) {
	now := time.now().unix()

	if ip in memory.hosts {
		mut profile := memory.hosts[ip]
		profile.count++
		profile.last_seen = now

		if !profile.is_mature {
			if profile.count > 10 && (now - profile.first_seen) > 300 {
				profile.is_mature = true
			}
		}

		memory.hosts[ip] = profile
		return false, profile.is_mature
	} else {
		memory.hosts[ip] = HostProfile{
			count: 1
			first_seen: now
			last_seen: now
			is_mature: false
		}
		return true, false
	}
}

fn calculate_process_multiplier(process string) f64 {
	if process == 'unknown' {
		return 1.5
	}
	if process in safe_processes {
		return 0.6
	}
	return 1.0
}

fn get_connections(mut cache DNSCache, mut memory TrafficMemory, is_spike bool, calibrating bool) []TrafficLog {
	res := os.execute('ss -tunap')
	if res.exit_code != 0 {
		return []TrafficLog{}
	}

	mut logs := []TrafficLog{}
	lines := res.output.split('\n')

	for line in lines {
		if !line.contains('ESTAB') {
			continue
		}

		fields := line.split_any(' \t')
		mut clean := []string{}
		for f in fields {
			if f.len > 0 {
				clean << f
			}
		}

		if clean.len < 5 {
			continue
		}

		remote := clean[5]
		mut ip := ''
		mut port := 0

		if remote.contains(']:') {
			parts := remote.split(']:')
			ip = parts[0].replace('[', '')
			port = parts[1].int()
		} else if remote.contains(':') {
			parts := remote.split(':')
			ip = parts[0]
			port = parts[1].int()
		}

		if ip == '' {
			continue
		}

		proc_name := extract_process_safe(line)
		host := resolve_host_safe(mut cache, ip)

		mut risk := 0.0
		mut tags := []string{}
		mut raw_entropy := 0.0

		is_private := is_private_ip(ip)
		is_raw_ip := host == ip

		if !is_private {
			is_new, is_mature := update_memory(mut memory, ip)

			if is_new && !calibrating {
				risk += 20
				tags << 'NEW_DESTINATION'
			} else if !is_mature && !calibrating {
				risk += 10
				tags << 'IMMATURE_HOST'
			}
		}

		if is_private {
			risk = 0
			tags << 'INTERNAL'
		} else {
			if is_raw_ip {
				risk += 15
				tags << 'DIRECT_IP'
			}
			ent_val, dom_score, dom_tags := analyze_domain_entropy(host, is_raw_ip)
			raw_entropy = ent_val
			risk += f64(dom_score)
			tags << dom_tags
		}

		if port in suspicious_ports {
			risk += 50
			tags << 'SUS_PORT'
		} else if port > 10000 && !is_private {
			risk += 15
			tags << 'RARE_PORT'
		}

		proc_mult := calculate_process_multiplier(proc_name)
		spike_mult := if is_spike { 1.3 } else { 1.0 }

		final_score := int(risk * proc_mult * spike_mult)

		tier := if final_score >= 80 {
			'CRITICAL'
		} else if final_score >= 50 {
			'HIGH'
		} else if final_score >= 25 {
			'MEDIUM'
		} else {
			'LOW'
		}

		behavior := if proc_mult < 1.0 {
			'Trusted App'
		} else if proc_mult > 1.2 {
			'Suspicious Process'
		} else {
			'Standard'
		}

		logs << TrafficLog{
			timestamp: time.now().format_ss()
			process: proc_name
			target_host: host
			target_ip: ip
			port: port
			risk_score: final_score
			risk_tier: tier
			tags: tags
			behavior_note: behavior
			raw_entropy: raw_entropy
			proc_mult: proc_mult
		}
	}
	return logs
}

fn print_dashboard(bw u64, baseline f64, spike bool, calib int, tracked int) {
	print('\033[H\033[J')
	println('${pink}${bold}  ★。＼｜／。★  VNS-E-II SENTIENT ENGINE  ★。／｜＼。★${reset}')

	status := if calib > 0 {
		'${yellow}LEARNING MODE (${calib}s)${reset}'
	} else if spike {
		'${red}TRAFFIC ANOMALY!${reset}'
	} else {
		'${cyan}ACTIVE MONITORING${reset}'
	}

	println('${white}  ┌──────────────────────────────────────────────┐${reset}')
	println('${white}  │ Traffic   : ${bold}${bw}${reset} B/s')
	println('${white}  │ Baseline  : ${grey}${baseline:.2f}${reset} B/s')
	println('${white}  │ Tracked   : ${purple}${tracked}${reset} unique hosts')
	println('${white}  │ Status    : ${status}')
	println('${white}  └──────────────────────────────────────────────┘${reset}')
	println('')
}

fn print_alert(log TrafficLog) {
	color := if log.risk_score >= 80 {
		red
	} else if log.risk_score >= 50 {
		purple
	} else {
		yellow
	}

	println('${color}  [!] BEHAVIORAL ANOMALY DETECTED${reset}')
	println('  ${white}TARGET  : ${cyan}${log.target_host}${reset}')
	println('  ${white}ADDRESS : ${log.target_ip}:${log.port}')
	println('  ${white}PROCESS : ${bold}${log.process}${reset}')
	println('')
	println('  ${white}--- METADATA DUMP ---${reset}')
	println('  ${grey}Timestamp   : ${log.timestamp}')
	println('  ${grey}Entropy     : ${log.raw_entropy:.4f}')
	println('  ${grey}Proc Mult   : ${log.proc_mult}x')
	println('  ${grey}Behavior    : ${log.behavior_note}')
	println('  ${grey}Risk Tags   : ${log.tags}')
	println('  ${grey}Final Score : ${color}${log.risk_score} (${log.risk_tier})${reset}')
	println('  ${pink}---------------------------------------------${reset}')
}

fn export_log(log TrafficLog) {
	data := json.encode(log)
	mut f := os.open_append('vns_e_ii_log.json') or { return }
	f.writeln(data) or {}
	f.close()
}

fn main() {
	mut stats := SysStats{
		prev_bytes: get_system_bytes()
		ema_baseline: 0.0
		accumulated: 0
		calibration: 5
		last_checked: time.now().unix()
	}

	mut cache := DNSCache{
		entries: map[string]string{}
	}

	mut memory := TrafficMemory{
		hosts: map[string]HostProfile{}
	}

	for {
		now := time.now().unix()
		curr_bytes := get_system_bytes()
		mut diff := now - stats.last_checked
		if diff < 1 {
			diff = 1
		}

		bw := (curr_bytes - stats.prev_bytes) / u64(diff)

		if stats.calibration > 0 {
			stats.accumulated += bw
			stats.calibration--

			get_connections(mut cache, mut memory, false, true)

			if stats.calibration == 0 {
				stats.ema_baseline = f64(stats.accumulated) / 5.0
			}
			print_dashboard(bw, 0.0, false, stats.calibration + 1, memory.hosts.len)
		} else {
			is_spike := stats.ema_baseline > 2000 && f64(bw) > (stats.ema_baseline * 3.0)

			print_dashboard(bw, stats.ema_baseline, is_spike, 0, memory.hosts.len)

			conns := get_connections(mut cache, mut memory, is_spike, false)

			for log in conns {
				mut final_log := log
				if is_spike && !final_log.tags.contains('INTERNAL') {
					final_log.tags << 'BW_SPIKE_CORR'
				}

				if final_log.risk_score >= 35 {
					print_alert(final_log)
					export_log(final_log)
				}
			}

			alpha := 0.2
			stats.ema_baseline = (alpha * f64(bw)) + ((1.0 - alpha) * stats.ema_baseline)
		}

		stats.prev_bytes = curr_bytes
		stats.last_checked = now

		time.sleep(1 * time.second)
	}
}
