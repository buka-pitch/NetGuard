package capture

import (
    "bufio"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "strconv"
    "strings"
)

const (
    procNetTCP  = "/proc/net/tcp"
    procNetTCP6 = "/proc/net/tcp6"
    procNetUDP  = "/proc/net/udp"
    procNetUDP6 = "/proc/net/udp6"
    procNetRaw  = "/proc/net/raw"
    procNetRaw6 = "/proc/net/raw6"
    procNetICMP = "/proc/net/icmp"
    procNetIC6  = "/proc/net/icmp6"
)

type TCPState int

const (
    TCPEstablished TCPState = 1
    TCPSynSent     TCPState = 2
    TCPSynRecv     TCPState = 3
    TCPFinWait1    TCPState = 4
    TCPFinWait2    TCPState = 5
    TCPTimeWait    TCPState = 6
    TCPClose       TCPState = 7
    TCPCloseWait   TCPState = 8
    TCPLastAck     TCPState = 9
    TCPListen      TCPState = 10
    TCPClosing     TCPState = 11
)

var tcpStateNames = map[TCPState]string{
    TCPEstablished: "ESTABLISHED",
    TCPSynSent:     "SYN_SENT",
    TCPSynRecv:     "SYN_RECV",
    TCPFinWait1:    "FIN_WAIT1",
    TCPFinWait2:    "FIN_WAIT2",
    TCPTimeWait:    "TIME_WAIT",
    TCPClose:       "CLOSE",
    TCPCloseWait:   "CLOSE_WAIT",
    TCPLastAck:     "LAST_ACK",
    TCPListen:      "LISTEN",
    TCPClosing:     "CLOSING",
}

func readProcNet(path string, proto string) (map[ConnectionKey]Connection, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    result := make(map[ConnectionKey]Connection)

    scanner := bufio.NewScanner(f)
    scanner.Scan()

    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Fields(line)
        if len(fields) < 12 {
            continue
        }

        local := parseHexAddr(fields[1])
        remote := parseHexAddr(fields[2])
        stateCode, _ := strconv.ParseInt(fields[3], 16, 32)
        txq, _ := strconv.ParseUint(strings.Split(fields[4], ":")[0], 16, 32)
        rxq, _ := strconv.ParseUint(strings.Split(fields[4], ":")[1], 16, 32)
        uid, _ := strconv.Atoi(fields[7])
        inode, _ := strconv.ParseUint(fields[9], 10, 64)

        state := TCPState(stateCode)

        conn := Connection{
            LocalAddr:  local.IP,
            LocalPort:  local.Port,
            RemoteAddr: remote.IP,
            RemotePort: remote.Port,
            Protocol:   proto,
            State:      tcpStateNames[state],
            UID:        uid,
            Inode:      inode,
            TxQueue:    txq,
            RxQueue:    rxq,
        }

        key := ConnectionKey{
            Proto:      proto,
            LocalAddr:  local.IP.String(),
            LocalPort:  local.Port,
            RemoteAddr: remote.IP.String(),
            RemotePort: remote.Port,
        }

        result[key] = conn
    }

    return result, nil
}

type hexAddr struct {
    IP   net.IP
    Port int
}

func parseHexAddr(s string) hexAddr {
    parts := strings.Split(s, ":")
    if len(parts) != 2 {
        return hexAddr{}
    }

    port, _ := strconv.ParseInt(parts[1], 16, 32)

    rawIP := parts[0]
    var ip net.IP
    if len(rawIP) == 8 {
        val, _ := strconv.ParseUint(rawIP, 16, 32)
        ip = net.IPv4(
            byte(val&0xFF),
            byte((val>>8)&0xFF),
            byte((val>>16)&0xFF),
            byte((val>>24)&0xFF),
        )
    } else {
        ip = parseIPv6(rawIP)
    }

    return hexAddr{IP: ip, Port: int(port)}
}

func parseIPv6(s string) net.IP {
    ip := make(net.IP, 16)
    for i := 0; i < 8 && i*8+8 <= len(s); i++ {
        part := s[i*8 : i*8+8]
        val, _ := strconv.ParseUint(part, 16, 32)
        ip[i*2] = byte(val >> 8)
        ip[i*2+1] = byte(val & 0xFF)
    }
    return ip
}

type ProcMapper struct{}

func NewProcMapper() *ProcMapper {
    return &ProcMapper{}
}

func (p *ProcMapper) Lookup(inode uint64) (int, string) {
    procRoot := "/proc"
    entries, err := os.ReadDir(procRoot)
    if err != nil {
        return 0, ""
    }

    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }
        pid, err := strconv.Atoi(entry.Name())
        if err != nil {
            continue
        }

        fdDir := filepath.Join(procRoot, entry.Name(), "fd")
        fdEntries, err := os.ReadDir(fdDir)
        if err != nil {
            continue
        }

        for _, fd := range fdEntries {
            link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
            if err != nil {
                continue
            }
            if strings.Contains(link, "socket:") {
                var fileInode uint64
                n, _ := fmt.Sscanf(link, "socket:[%d]", &fileInode)
                if n == 1 && fileInode == inode {
                    comm, _ := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm"))
                    return pid, strings.TrimSpace(string(comm))
                }
            }
        }
    }

    return 0, ""
}

func (p *ProcMapper) LookupPID(pid int) string {
    comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(comm))
}

func ResolveProcInodes() (map[uint64]int, error) {
    result := make(map[uint64]int)
    procRoot := "/proc"

    entries, err := os.ReadDir(procRoot)
    if err != nil {
        return nil, err
    }

    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }
        pid, err := strconv.Atoi(entry.Name())
        if err != nil {
            continue
        }

        fdDir := filepath.Join(procRoot, entry.Name(), "fd")
        fdEntries, err := os.ReadDir(fdDir)
        if err != nil {
            continue
        }

        for _, fd := range fdEntries {
            link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
            if err != nil {
                continue
            }
            if strings.Contains(link, "socket:") {
                var inode uint64
                if _, err := fmt.Sscanf(link, "socket:[%d]", &inode); err == nil {
                    result[inode] = pid
                }
            }
        }
    }

    return result, nil
}

func ReadProcCmdline(pid int) string {
    data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
    if err != nil {
        return ""
    }
    return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

func ReadProcExe(pid int) string {
    link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
    if err != nil {
        return ""
    }
    return link
}

func ReadProcPPID(pid int) int {
    data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
    if err != nil {
        return 0
    }
    for _, line := range strings.Split(string(data), "\n") {
        if strings.HasPrefix(line, "PPid:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                ppid, _ := strconv.Atoi(fields[1])
                return ppid
            }
        }
    }
    return 0
}

func ReadProcParentComm(pid int) string {
    ppid := ReadProcPPID(pid)
    if ppid == 0 {
        return ""
    }
    comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(ppid), "comm"))
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(comm))
}

func ReadProcGPID(pid int) int {
    ppid := ReadProcPPID(pid)
    if ppid == 0 {
        return 0
    }
    return ReadProcPPID(ppid)
}

func ReadProcGComm(pid int) string {
    ppid := ReadProcPPID(pid)
    if ppid <= 1 {
        return ""
    }
    gpid := ReadProcPPID(ppid)
    if gpid == 0 {
        return ""
    }
    comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(gpid), "comm"))
    if err != nil {
        return ""
    }
    return strings.TrimSpace(string(comm))
}

func ReadProcAll(pid int) (cmdline, exe string, ppid int, pcomm string, gpid int, gcomm string) {
    cmdline = ReadProcCmdline(pid)
    exe = ReadProcExe(pid)
    ppid = ReadProcPPID(pid)
    pcomm = ReadProcParentComm(pid)
    gpid = ReadProcGPID(pid)
    gcomm = ReadProcGComm(pid)
    return
}

type SynSentEntry struct {
    PID     int
    Comm    string
    Cmdline string
    Exe     string
    IP      string
    Port    int
}

// ScanSynSent reads /proc/net/tcp{,6} and returns connections in SYN_SENT state
// with resolved PID and process info. Used as fallback scanner for firewall
// pending approval detection.
func ScanSynSent() []SynSentEntry {
    entries := readSynSent(procNetTCP)
    entries6 := readSynSent(procNetTCP6)
    entries = append(entries, entries6...)
    if len(entries) == 0 {
        return nil
    }

    inodes := make(map[uint64]struct{})
    for _, e := range entries {
        inodes[e.inode] = struct{}{}
    }
    pm, err := ResolveProcInodes()
    if err != nil {
        result := make([]SynSentEntry, len(entries))
        for i, e := range entries {
            result[i] = SynSentEntry{IP: e.ip, Port: e.port}
        }
        return result
    }

    seen := make(map[string]bool)
    var result []SynSentEntry
    for _, e := range entries {
        key := e.ip + ":" + strconv.Itoa(e.port)
        if seen[key] {
            continue
        }
        seen[key] = true
        entry := SynSentEntry{IP: e.ip, Port: e.port}
        if pid, ok := pm[e.inode]; ok {
            entry.PID = pid
            entry.Comm = NewProcMapper().LookupPID(pid)
            cmdline, exe, _, _, _, _ := ReadProcAll(pid)
            entry.Cmdline = cmdline
            entry.Exe = exe
        }
        result = append(result, entry)
    }
    return result
}

type synSentInfo struct {
    inode uint64
    ip    string
    port  int
}

func readSynSent(path string) []synSentInfo {
    f, err := os.Open(path)
    if err != nil {
        return nil
    }
    defer f.Close()

    var result []synSentInfo
    scanner := bufio.NewScanner(f)
    scanner.Scan()
    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Fields(line)
        if len(fields) < 12 {
            continue
        }
        remote := parseHexAddr(fields[2])
        stateCode, _ := strconv.ParseInt(fields[3], 16, 32)
        state := TCPState(stateCode)
        if state != TCPSynSent {
            continue
        }
        inode, _ := strconv.ParseUint(fields[9], 10, 64)
        if !remote.IP.IsUnspecified() && remote.IP.IsGlobalUnicast() {
            result = append(result, synSentInfo{
                inode: inode,
                ip:    remote.IP.String(),
                port:  remote.Port,
            })
        }
    }
    return result
}
