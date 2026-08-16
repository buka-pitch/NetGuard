package capture

import "net"

type Connection struct {
    PID          int      `json:"pid"`
    UID          int      `json:"uid"`
    Comm         string   `json:"comm"`
    Cmdline      string   `json:"cmdline"`
    Exe          string   `json:"exe"`
	PPID         int      `json:"ppid"`
	PComm        string   `json:"pcomm"`
	GPID         int      `json:"gpid,omitempty"`
	GComm        string   `json:"gcomm,omitempty"`
    LocalAddr    net.IP   `json:"local_addr"`
    LocalPort    int      `json:"local_port"`
    RemoteAddr   net.IP   `json:"remote_addr"`
    RemotePort   int      `json:"remote_port"`
    Protocol     string   `json:"protocol"`
    State        string   `json:"state"`
    Inode        uint64   `json:"inode"`
    TxQueue      uint64   `json:"tx_queue"`
    RxQueue      uint64   `json:"rx_queue"`
    CreatedAt    int64    `json:"created_at"`
	Domain       string   `json:"domain,omitempty"`
	DomainSource string   `json:"domain_source,omitempty"`
	TLSHost      string   `json:"tls_sni,omitempty"`
	HTTPHost     string   `json:"http_host,omitempty"`
	PreExisting  bool     `json:"pre_existing,omitempty"`
	IsVPN        bool     `json:"is_vpn,omitempty"`
	Incoming     bool     `json:"incoming,omitempty"`
}

var VPNPorts = map[int]struct{}{
    51820: {}, // WireGuard
    51821: {}, // WireGuard alt
    1194:  {}, // OpenVPN
    1195:  {}, // OpenVPN alt
    500:   {}, // IKE/IPSec
    4500:  {}, // IPSec NAT-T
    1701:  {}, // L2TP
    1723:  {}, // PPTP
    60000: {}, // Tailscale alt
}

type ConnectionEvent struct {
    Type      EventType
    Connection
}

type EventType int

const (
    EventNew  EventType = iota
    EventClose
    EventUpdate
)

type ConnectionKey struct {
    Proto      string
    LocalAddr  string
    LocalPort  int
    RemoteAddr string
    RemotePort int
}
