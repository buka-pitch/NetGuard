package capture

import (
	"context"
	"net"
	"netmon/internal/dnsmon"
	"netmon/internal/logutil"
	"sync"
	"time"
)

type procInfo struct {
    PID         int
    Comm        string
    Cmdline     string
    Exe         string
    ParentPID   int
    ParentComm  string
    GrandPID    int
    GrandComm   string
}

type domainEntry struct {
    domain    string
    expiresAt int64
}

type Poller struct {
    mu            sync.RWMutex
    interval      time.Duration
    prev          map[ConnectionKey]Connection
    inodeCache    map[uint64]procInfo
    domainCache   map[string]domainEntry
    dnsMon        *dnsmon.Monitor
    mapper        *ProcMapper
    lastInodeScan time.Time
    currentConns  []Connection
    lastSynCount  int
    firstPoll     bool
    askOnStart    bool
    synSentSeen   map[ConnectionKey]bool
    done          chan struct{}
}

func NewPoller(interval time.Duration, dnsMon *dnsmon.Monitor, askOnStart bool) *Poller {
    p := &Poller{
        interval:    interval,
        prev:        make(map[ConnectionKey]Connection),
        inodeCache:  make(map[uint64]procInfo),
        domainCache: make(map[string]domainEntry),
        dnsMon:      dnsMon,
        mapper:      NewProcMapper(),
        firstPoll:   true,
        askOnStart:  askOnStart,
        synSentSeen: make(map[ConnectionKey]bool),
        done:        make(chan struct{}),
    }
    go p.dnsResolver()
    return p
}

// Stop signals the Start loop and the dnsResolver goroutine to exit. Safe to
// call multiple times; safe to call before Start.
func (p *Poller) Stop() {
    select {
    case <-p.done:
        // already closed
    default:
        close(p.done)
    }
}

func (p *Poller) dnsResolver() {
    // wait for first tick after start
    timer := time.NewTimer(30 * time.Second)
    defer timer.Stop()
    for {
        select {
        case <-p.done:
            return
        case <-timer.C:
        }
        p.mu.RLock()
        conns := p.currentConns
        p.mu.RUnlock()

        now := time.Now().Unix()
        for _, c := range conns {
            if c.RemoteAddr == nil {
                continue
            }
            ip := c.RemoteAddr.String()
            p.mu.Lock()
            entry, ok := p.domainCache[ip]
            if ok && entry.expiresAt > now {
                p.mu.Unlock()
                continue
            }
            p.mu.Unlock()

            ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
            names, err := net.DefaultResolver.LookupAddr(ctx, ip)
            cancel()

            p.mu.Lock()
            if err == nil && len(names) > 0 {
                p.domainCache[ip] = domainEntry{domain: names[0], expiresAt: time.Now().Add(1 * time.Hour).Unix()}
            } else {
                // cache negative result too, shorter TTL
                p.domainCache[ip] = domainEntry{expiresAt: time.Now().Add(5 * time.Minute).Unix()}
            }
            // also try DNS monitor as fallback
            if p.dnsMon != nil {
                if d, ok := p.dnsMon.Lookup(ip); ok {
                    p.domainCache[ip] = domainEntry{domain: d, expiresAt: time.Now().Add(1 * time.Hour).Unix()}
                }
            }
            p.mu.Unlock()
        }
        timer.Reset(30 * time.Second)
    }
}

// Start runs the poll loop until ctx is cancelled or Stop is called.
func (p *Poller) Start(ctx context.Context, events chan<- ConnectionEvent) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-ticker.C:
			p.poll(events)
		}
	}
}

func (p *Poller) poll(events chan<- ConnectionEvent) {
    prevLen := len(p.prev)
    current := make(map[ConnectionKey]Connection, prevLen)

    for _, path := range []string{procNetTCP, procNetTCP6, procNetUDP, procNetUDP6, procNetRaw, procNetRaw6, procNetICMP, procNetIC6} {
        proto := "tcp"
        if path == procNetTCP6 {
            proto = "tcp6"
        }
        if path == procNetUDP {
            proto = "udp"
        }
        if path == procNetUDP6 {
            proto = "udp6"
        }
        if path == procNetRaw {
            proto = "raw"
        }
        if path == procNetRaw6 {
            proto = "raw6"
        }
        if path == procNetICMP {
            proto = "icmp"
        }
        if path == procNetIC6 {
            proto = "icmp6"
        }

        conns, err := readProcNet(path, proto)
        if err != nil {
            logutil.Warn("error reading %s: %v", path, err)
            continue
        }

        for key, conn := range conns {
            current[key] = conn
        }
    }

    // fill inode cache for any uncached inodes
    uncached := make(map[uint64]struct{}, prevLen/4)
    for _, conn := range current {
        if _, ok := p.inodeCache[conn.Inode]; !ok {
            uncached[conn.Inode] = struct{}{}
        }
    }
    // also check for inodes from closing connections
    for _, conn := range p.prev {
        if _, ok := p.inodeCache[conn.Inode]; !ok {
            uncached[conn.Inode] = struct{}{}
        }
    }
    if len(uncached) > 0 {
        im, err := ResolveProcInodes()
        if err == nil {
            for inode, pid := range im {
                if _, want := uncached[inode]; want {
                    cmdline, exe, ppid, pcomm, gpid, gcomm := ReadProcAll(pid)
                    p.inodeCache[inode] = procInfo{
                        PID:        pid,
                        Comm:       p.mapper.LookupPID(pid),
                        Cmdline:    cmdline,
                        Exe:        exe,
                        ParentPID:  ppid,
                        ParentComm: pcomm,
                        GrandPID:   gpid,
                        GrandComm:  gcomm,
                    }
                }
            }
        }
    }

    synCount := 0
    now := time.Now().UnixMilli()

    // rebuild synSentSeen for this poll cycle
    freshSyn := make(map[ConnectionKey]bool, prevLen/8)
    for key, conn := range current {
        if conn.State == "SYN_SENT" {
            synCount++
            freshSyn[key] = true
        }
        // mark pre-existing (first poll) unless askOnStart forces a fresh queue
        conn.PreExisting = p.firstPoll && !p.askOnStart
        // detect known VPN ports
        if _, ok := VPNPorts[conn.RemotePort]; ok {
            conn.IsVPN = true
        }
        // detect incoming: ESTABLISHED or SYN_RECV without prior SYN_SENT tracking
        // (when askOnStart is on we still want to flag first-poll inbound sockets)
        if (!p.firstPoll || p.askOnStart) && (conn.State == "ESTABLISHED" || conn.State == "SYN_RECV") && !p.synSentSeen[key] && conn.RemoteAddr != nil && !conn.RemoteAddr.IsLoopback() && !conn.RemoteAddr.IsUnspecified() {
            conn.Incoming = true
        }
        // populate domain from cache — DNS monitor takes priority
        if conn.RemoteAddr != nil {
            ip := conn.RemoteAddr.String()
            if p.dnsMon != nil {
                if d, ok := p.dnsMon.Lookup(ip); ok {
                    conn.Domain = d
                    conn.DomainSource = "dns_monitor"
                }
            }
            if conn.Domain == "" {
                if entry, ok := p.domainCache[ip]; ok && entry.domain != "" {
                    conn.Domain = entry.domain
                    conn.DomainSource = "reverse_dns"
                }
            }
        }

        if existing, ok := p.prev[key]; !ok {
            if info, ok := p.inodeCache[conn.Inode]; ok {
                conn.PID = info.PID
                conn.Comm = info.Comm
                conn.Cmdline = info.Cmdline
                conn.Exe = info.Exe
                conn.PPID = info.ParentPID
                conn.PComm = info.ParentComm
                conn.GPID = info.GrandPID
                conn.GComm = info.GrandComm
            }
            conn.CreatedAt = now
            current[key] = conn
            p.emit(events, EventNew, conn)
        } else {
            conn.PID = existing.PID
            conn.Comm = existing.Comm
            conn.Cmdline = existing.Cmdline
            conn.Exe = existing.Exe
            conn.PPID = existing.PPID
            conn.PComm = existing.PComm
            conn.GPID = existing.GPID
            conn.GComm = existing.GComm
            conn.CreatedAt = existing.CreatedAt
            current[key] = conn
            if existing.State != conn.State {
                p.emit(events, EventUpdate, conn)
            }
        }
    }
    p.synSentSeen = freshSyn

    for key, conn := range p.prev {
        if _, stillHere := current[key]; !stillHere {
            p.emit(events, EventClose, conn)
        }
    }

    p.lastSynCount = synCount
    p.firstPoll = false
    p.mu.Lock()
    p.prev = current
    snap := make([]Connection, 0, len(current))
    for _, c := range current {
        if c.PID > 0 || c.State == "ESTABLISHED" {
            snap = append(snap, c)
        }
    }
    p.currentConns = snap
    p.mu.Unlock()
}

func (p *Poller) Snapshot() []Connection {
    p.mu.RLock()
    defer p.mu.RUnlock()
    if len(p.currentConns) == 0 {
        return nil
    }
    out := make([]Connection, len(p.currentConns))
    copy(out, p.currentConns)
    return out
}

func (p *Poller) emit(events chan<- ConnectionEvent, typ EventType, conn Connection) {
    ev := ConnectionEvent{
        Type:       typ,
        Connection: conn,
    }
    select {
    case events <- ev:
    default:
        logutil.Warn("WARNING: event channel full, dropping")
    }
}
