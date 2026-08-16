package firewall

import (
	"fmt"
	"netmon/internal/logutil"
	"os/exec"
	"strings"
)

const table = "inet netmon"
const outChain = "output"
const inChain = "input"
const outSet = "allowed"
const inSet = "allowed_in"
const dnsSet = "dns_servers"

func nft(args ...string) error {
	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w\nstderr=%q", strings.Join(args, " "), err, string(out))
	}
	return nil
}

func (m *Manager) Init() error {
	if err := nft("add", "table", table); err != nil {
		return err
	}

	// --- output chain ---
	_ = nft("flush", "chain", table, outChain)
	_ = nft("delete", "set", table, outSet)
	_ = nft("delete", "chain", table, outChain)

	if err := nft("add", "chain", table, outChain, `{ type filter hook output priority 0; policy drop; }`); err != nil {
		return err
	}
	logutil.Info("firewall: output chain created, policy drop")

	if err := nft("add", "rule", table, outChain, "ct state established,related accept"); err != nil {
		return err
	}
	logutil.Info("firewall: output — ct state established,related accept")

	if err := nft("add", "rule", table, outChain, "ip daddr 127.0.0.0/8 accept"); err != nil {
		return err
	}
	if err := nft("add", "rule", table, outChain, "ip6 daddr ::1 accept"); err != nil {
		return err
	}
	logutil.Info("firewall: output — loopback accept")

	preseedRules := []struct{ ip, proto string; port int }{
		{"0.0.0.0/0", "udp", 53},
		{"0.0.0.0/0", "tcp", 53},
		{"0.0.0.0/0", "udp", 123},
		{"0.0.0.0/0", "udp", 67},
		{"0.0.0.0/0", "udp", 68},
		{"0.0.0.0/0", "udp", 546},
	}
	for _, r := range preseedRules {
		rule := fmt.Sprintf("ip daddr %s meta l4proto %s th dport %d accept", r.ip, r.proto, r.port)
		if err := nft("add", "rule", table, outChain, rule); err != nil {
			logutil.Warn("firewall: init preseed rule %s: %v", rule, err)
		}
	}
	logutil.Info("firewall: output — %d preseed rules", len(preseedRules))

	if err := nft("add", "set", table, outSet, `{ type ipv4_addr . inet_proto . inet_service; }`); err != nil {
		return err
	}
	if err := nft("add", "rule", table, outChain, "ip daddr . meta l4proto . th dport", "@"+outSet, "accept"); err != nil {
		return err
	}
	logutil.Info("firewall: output — allowed set accept")

	// --- input chain ---
	_ = nft("flush", "chain", table, inChain)
	_ = nft("delete", "set", table, inSet)
	_ = nft("delete", "chain", table, inChain)

	if err := nft("add", "chain", table, inChain, `{ type filter hook input priority 0; policy drop; }`); err != nil {
		return err
	}
	logutil.Info("firewall: input chain created, policy drop")

	if err := nft("add", "rule", table, inChain, "ct state established,related accept"); err != nil {
		return err
	}
	logutil.Info("firewall: input — ct state established,related accept")

	if err := nft("add", "rule", table, inChain, "ip saddr 127.0.0.0/8 accept"); err != nil {
		return err
	}
	if err := nft("add", "rule", table, inChain, "ip6 saddr ::1 accept"); err != nil {
		return err
	}
	logutil.Info("firewall: input — loopback accept")

	if err := nft("add", "set", table, inSet, `{ type ipv4_addr . inet_proto . inet_service; }`); err != nil {
		return err
	}
	if err := nft("add", "rule", table, inChain, "ip saddr . meta l4proto . th dport", "@"+inSet, "accept"); err != nil {
		return err
	}
	logutil.Info("firewall: input — allowed_in set accept")

	// --- DNS server tracking set ---
	_ = nft("delete", "set", table, dnsSet)
	if err := nft("add", "set", table, dnsSet, `{ type ipv4_addr; flags timeout; }`); err != nil {
		logutil.Warn("firewall: dns_servers set could not be created: %v", err)
	}
	logutil.Info("firewall: dns_servers set created")
	return nil
}

func (m *Manager) DeleteAll() error {
	_ = nft("flush", "chain", table, outChain)
	_ = nft("delete", "set", table, outSet)
	_ = nft("delete", "chain", table, outChain)
	_ = nft("flush", "chain", table, inChain)
	_ = nft("delete", "set", table, inSet)
	_ = nft("delete", "chain", table, inChain)
	_ = nft("delete", "table", table)
	return nil
}

func Key(ip, proto string, port int) string {
	return fmt.Sprintf("%s . %s . %d", ip, proto, port)
}

func (m *Manager) Allow(ip, proto string, port int) error {
	return nft("add", "element", table, outSet, `{ `+Key(ip, proto, port)+` }`)
}

func (m *Manager) Revoke(ip, proto string, port int) error {
	return nft("delete", "element", table, outSet, `{ `+Key(ip, proto, port)+` }`)
}

func (m *Manager) AllowIn(ip, proto string, port int) error {
	return nft("add", "element", table, inSet, `{ `+Key(ip, proto, port)+` }`)
}

func (m *Manager) RevokeIn(ip, proto string, port int) error {
	return nft("delete", "element", table, inSet, `{ `+Key(ip, proto, port)+` }`)
}

func (m *Manager) AddDNSServer(ip string) error {
	return nft("add", "element", table, dnsSet, `{ `+ip+` timeout 1h }`)
}

func (m *Manager) RemoveDNSServer(ip string) error {
	return nft("delete", "element", table, dnsSet, `{ `+ip+` }`)
}

func (m *Manager) ListDNSServers() ([]string, error) {
	out, err := exec.Command("nft", "list", "set", table, dnsSet).Output()
	if err != nil {
		return nil, err
	}
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ".") && !strings.HasPrefix(line, "set") && !strings.HasPrefix(line, "{") && !strings.HasPrefix(line, "}") {
			ip := strings.Fields(line)[0]
			servers = append(servers, ip)
		}
	}
	return servers, nil
}

func (m *Manager) SetPolicy(policy string) error {
	if err := nft("add", "chain", table, outChain, `{ policy `+policy+`; }`); err != nil {
		return err
	}
	return nft("add", "chain", table, inChain, `{ policy `+policy+`; }`)
}

func (m *Manager) GetPolicy() (string, error) {
	out, err := exec.Command("nft", "list", "chain", table, outChain).Output()
	if err != nil {
		return "drop", err
	}
	if strings.Contains(string(out), "policy drop") {
		return "drop", nil
	}
	return "accept", nil
}

func (m *Manager) IsEnabled() bool {
	out, err := exec.Command("nft", "list", "chain", table, outChain).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "policy drop")
}

func (m *Manager) RuleCount() int {
	out, err := exec.Command("nft", "list", "chain", table, outChain).Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(string(out), "\n")
	count := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "\tip daddr") && strings.HasSuffix(l, "accept") {
			count++
		}
	}
	return count
}

func (m *Manager) Flush() error {
	return m.Init()
}

func (m *Manager) Restore() error {
	rules, err := m.LoadAllowlist()
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Direction == "in" {
			if r.Mode == "always" && r.IP != "0.0.0.0/0" {
				if err := m.AllowIn(r.IP, r.Proto, r.Port); err != nil {
					logutil.Error("firewall: restore AllowIn(%s, %s, %d): %v", r.IP, r.Proto, r.Port, err)
				}
			}
		} else {
			if r.Mode == "always" && r.IP != "0.0.0.0/0" {
				if err := m.Allow(r.IP, r.Proto, r.Port); err != nil {
					logutil.Error("firewall: restore Allow(%s, %s, %d): %v", r.IP, r.Proto, r.Port, err)
				}
			}
		}
	}
	return nil
}
