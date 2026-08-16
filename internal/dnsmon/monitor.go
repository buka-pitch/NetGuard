package dnsmon

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"netmon/internal/logutil"
)

type cacheEntry struct {
	domain    string
	expiresAt int64
	firstSeen int64
}

type Monitor struct {
	mu          sync.RWMutex
	cache       map[string]cacheEntry
	fd          int
	done        chan struct{}
	running     bool
	dnsIPsMu    sync.RWMutex
	dnsIPs      map[string]struct{}
	onNewDNSSrv func(ip string)
}

func NewMonitor() *Monitor {
	return &Monitor{
		cache:  make(map[string]cacheEntry),
		done:   make(chan struct{}),
		dnsIPs: make(map[string]struct{}),
	}
}

func (m *Monitor) SetOnNewDNSServer(fn func(ip string)) {
	m.dnsIPsMu.Lock()
	defer m.dnsIPsMu.Unlock()
	m.onNewDNSSrv = fn
}

func (m *Monitor) Start() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	m.fd = fd

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}

	tv := syscall.NsecToTimeval(1000 * 1000 * 1000)
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("setsockopt RCVTIMEO: %w", err)
	}

	m.running = true

	go m.loop()
	go m.cleanupLoop()

	logutil.Info("dnsmon: started raw socket listener")
	return nil
}

func (m *Monitor) Stop() {
	if m.running {
		m.running = false
		close(m.done)
		syscall.Close(m.fd)
	}
}

func (m *Monitor) loop() {
	buf := make([]byte, 65535)

	for {
		select {
		case <-m.done:
			return
		default:
		}

		n, _, err := syscall.Recvfrom(m.fd, buf, 0)
		if err != nil {
			continue
		}
		if n < 20 {
			continue
		}

		m.processPacket(buf[:n])
	}
}

func (m *Monitor) processPacket(pkt []byte) {
	if len(pkt) < 20 {
		return
	}

	versionIHL := pkt[0]
	ihl := int(versionIHL&0x0F) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	if pkt[9] != 17 {
		return
	}

	if ihl+8 > len(pkt) {
		return
	}

	srcPort := int(pkt[ihl])<<8 | int(pkt[ihl+1])
	dstPort := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])

	// we want DNS responses: dst port 53 (queries) or src port 53 (responses)
	isResponse := srcPort == 53
	isQuery := dstPort == 53

	if !isResponse && !isQuery {
		return
	}

	dnsStart := ihl + 8
	if dnsStart >= len(pkt) {
		return
	}

	if isResponse {
		m.handleDNSResponse(pkt[dnsStart:])
	}

	if isQuery {
		m.handleDNSQuery(pkt, ihl, dstPort)
	}
}

func (m *Monitor) handleDNSResponse(dnsPayload []byte) {
	parsed, err := ParseResponse(dnsPayload)
	if err != nil || len(parsed.Answers) == 0 {
		return
	}

	domain := parsed.Question
	now := time.Now().Unix()

	m.mu.Lock()
	for _, ans := range parsed.Answers {
		ip := ans.IP.String()
		ttl := int64(ans.TTL)
		if ttl < 60 {
			ttl = 60
		}
		if ttl > 86400 {
			ttl = 86400
		}

		existing, ok := m.cache[ip]
		if ok && existing.domain == domain {
			existing.expiresAt = now + ttl
			m.cache[ip] = existing
		} else {
			m.cache[ip] = cacheEntry{
				domain:    domain,
				expiresAt: now + ttl,
				firstSeen: now,
			}
		}
	}
	m.mu.Unlock()
}

func (m *Monitor) handleDNSQuery(pkt []byte, ihl int, dnsPort int) {
	if len(pkt) < ihl+12 {
		return
	}

	srcIP := net.IP(pkt[12:16]).String()
	if srcIP == "0.0.0.0" || srcIP == "127.0.0.1" {
		return
	}

	if dnsPort == 53 || dnsPort == 853 {
		m.dnsIPsMu.Lock()
		if _, exists := m.dnsIPs[srcIP]; !exists {
			m.dnsIPs[srcIP] = struct{}{}
			if m.onNewDNSSrv != nil {
				fn := m.onNewDNSSrv
				m.dnsIPsMu.Unlock()
				fn(srcIP)
				return
			}
		}
		m.dnsIPsMu.Unlock()
	}
}

func (m *Monitor) Lookup(ip string) (string, bool) {
	m.mu.RLock()
	entry, ok := m.cache[ip]
	m.mu.RUnlock()
	if !ok {
		return "", false
	}
	if entry.expiresAt <= time.Now().Unix() {
		m.mu.Lock()
		delete(m.cache, ip)
		m.mu.Unlock()
		return "", false
	}
	return entry.domain, true
}

func (m *Monitor) IsDNSServer(ip string) bool {
	m.dnsIPsMu.RLock()
	_, ok := m.dnsIPs[ip]
	m.dnsIPsMu.RUnlock()
	return ok
}

func (m *Monitor) CacheSize() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cache)
}

func (m *Monitor) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *Monitor) cleanup() {
	now := time.Now().Unix()
	m.mu.Lock()
	for ip, entry := range m.cache {
		if entry.expiresAt <= now {
			delete(m.cache, ip)
		}
	}
	m.mu.Unlock()
}

func (m *Monitor) DumpCache() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	dump := make(map[string]string, len(m.cache))
	for ip, entry := range m.cache {
		if entry.expiresAt > time.Now().Unix() {
			dump[ip] = entry.domain
		}
	}
	return dump
}