package firewall

type Rule struct {
	ID        int64  `json:"id"`
	ExePath   string `json:"exe_path"`
	Process   string `json:"process"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Mode      string `json:"mode"`
	Direction string `json:"direction,omitempty"`
	TTLSecs   int    `json:"ttl_secs,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

type Pending struct {
	ID          int64  `json:"id"`
	ExePath     string `json:"exe_path"`
	Process     string `json:"process"`
	ParentChain string `json:"parent_chain"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Proto       string `json:"proto"`
	Direction   string `json:"direction,omitempty"`
	Pid         int    `json:"pid"`
	Domain      string `json:"domain"`
	AppData     string `json:"app_data"`
	Source      string `json:"source,omitempty"` // "new" (default) or "preexisting"
	CreatedAt   int64  `json:"created_at"`
}

type Status struct {
	Enabled   bool   `json:"enabled"`
	Policy    string `json:"policy"` // "accept" or "drop"
	Rules     int    `json:"rules"`
	Pending   int    `json:"pending"`
	PanicMode bool   `json:"panic_mode"`
	PanicUntil int64 `json:"panic_until,omitempty"`
}

type AppAllowlistEntry struct {
	ID        int64  `json:"id"`
	ExePath   string `json:"exe_path"`
	Process   string `json:"process"`
	CreatedAt int64  `json:"created_at"`
}

type AppDenylistEntry struct {
	ID        int64  `json:"id"`
	ExePath   string `json:"exe_path"`
	Process   string `json:"process"`
	CreatedAt int64  `json:"created_at"`
}
