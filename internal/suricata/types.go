package suricata

type Alert struct {
    Timestamp  string `json:"timestamp"`
    SrcIP      string `json:"src_ip"`
    SrcPort    int    `json:"src_port"`
    DstIP      string `json:"dst_ip"`
    DstPort    int    `json:"dst_port"`
    Proto      string `json:"protocol"`
    Action     string `json:"action"`
    GID        int    `json:"gid"`
    Signature  string `json:"signature"`
    Category   string `json:"category"`
    Severity   int    `json:"severity"`
    HTTP       *HTTP  `json:"http,omitempty"`
    TLS        *TLS   `json:"tls,omitempty"`
    DNS        *DNS   `json:"dns,omitempty"`

    PID        int    `json:"pid,omitempty"`
    Comm       string `json:"comm,omitempty"`
    Cmdline    string `json:"cmdline,omitempty"`
    Exe        string `json:"exe,omitempty"`
    ParentPID  int    `json:"ppid,omitempty"`
    ParentComm string `json:"pcomm,omitempty"`
    Duration   string `json:"duration,omitempty"`
}

type HTTP struct {
    Hostname  string `json:"hostname"`
    URL       string `json:"url"`
    UserAgent string `json:"ua"`
    Method    string `json:"method"`
    Status    int    `json:"status"`
    Mime      string `json:"mime"`
    Length    int    `json:"length"`
}

type TLS struct {
    Subject   string `json:"subject"`
    IssuerDN  string `json:"issuerdn"`
    Fingerprint string `json:"fingerprint"`
    SNI       string `json:"sni"`
    Version   string `json:"version"`
}

type DNS struct {
    Type      string `json:"type"`
    Query     string `json:"query"`
    RCode     string `json:"rcode"`
    Answers   []DNSAnswer `json:"answers"`
}

type DNSAnswer struct {
    Name string `json:"name"`
    Type string `json:"type"`
    Data string `json:"data"`
}

type Status struct {
    Running    bool   `json:"running"`
    Installed  bool   `json:"installed"`
    ServiceOk  bool   `json:"service_ok"`
    Version    string `json:"version"`
    Uptime     string `json:"uptime"`
}

type RuleFile struct {
    Name    string `json:"name"`
    Path    string `json:"path"`
    Enabled bool   `json:"enabled"`
    Count   int    `json:"count"`
}

type ConfigForm struct {
    HomeNet     []string `json:"home_net"`
    Interface   string   `json:"interface"`
    RulePath    string   `json:"rule_path"`
    RuleFiles   []string `json:"rule_files"`
    CommunityID bool     `json:"community_id"`
}

type Stats struct {
    PacketsTotal  int64   `json:"packets_total"`
    PacketsDrop   int64   `json:"packets_drop"`
    AlertsTotal   int64   `json:"alerts_total"`
    AlertsPerSec  float64 `json:"alerts_per_sec"`
    MemUsage      int64   `json:"mem_usage"`
    Uptime        string  `json:"uptime"`
}

type eveFlow struct {
    Timestamp  string `json:"timestamp"`
    EventType  string `json:"event_type"`
    SrcIP      string `json:"src_ip"`
    SrcPort    int    `json:"src_port"`
    DestIP     string `json:"dest_ip"`
    DestPort   int    `json:"dest_port"`
    Proto      string `json:"proto"`
    Alert      *struct {
        Action    string `json:"action"`
        GID       int    `json:"gid"`
        Signature string `json:"signature"`
        Category  string `json:"category"`
        Severity  int    `json:"severity"`
    } `json:"alert"`
    HTTP *struct {
        Hostname  string `json:"hostname"`
        URL       string `json:"url"`
        UserAgent string `json:"ua"`
        Method    string `json:"method"`
        Status    int    `json:"status"`
        Mime      string `json:"mime"`
        Length    int    `json:"length"`
    } `json:"http"`
    TLS *struct {
        Subject     string `json:"subject"`
        IssuerDN    string `json:"issuerdn"`
        Fingerprint string `json:"fingerprint"`
        SNI         string `json:"sni"`
        Version     string `json:"version"`
    } `json:"tls"`
    DNS *struct {
        Type    string `json:"type"`
        Query   string `json:"query"`
        RCode   string `json:"rcode"`
        Answers []struct {
            Name string `json:"name"`
            Type string `json:"type"`
            Data string `json:"data"`
        } `json:"answers"`
    } `json:"dns"`
    Stats *struct {
        Uptime  int `json:"uptime"`
        Capture *struct {
            KernelPackets int64 `json:"kernel_packets"`
            KernelDrops   int64 `json:"kernel_drops"`
        } `json:"capture"`
        Detect *struct {
            Alert int64 `json:"alert"`
        } `json:"detect"`
        Flow *struct {
            Memuse int64 `json:"memuse"`
        } `json:"flow"`
        Tcp *struct {
            Memuse int64 `json:"memuse"`
        } `json:"tcp"`
    } `json:"stats"`
}
