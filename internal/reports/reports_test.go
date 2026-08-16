package reports

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestCollectUsesOpenConnectionsAndTopPorts(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	schema := `
	CREATE TABLE connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pid INTEGER NOT NULL DEFAULT 0,
		uid INTEGER NOT NULL DEFAULT 0,
		comm TEXT NOT NULL DEFAULT '',
		cmdline TEXT NOT NULL DEFAULT '',
		exe TEXT NOT NULL DEFAULT '',
		ppid INTEGER NOT NULL DEFAULT 0,
		pcomm TEXT NOT NULL DEFAULT '',
		local_addr TEXT NOT NULL DEFAULT '',
		local_port INTEGER NOT NULL DEFAULT 0,
		remote_addr TEXT NOT NULL DEFAULT '',
		remote_port INTEGER NOT NULL DEFAULT 0,
		protocol TEXT NOT NULL DEFAULT 'tcp',
		state TEXT NOT NULL DEFAULT '',
		tx_queue INTEGER NOT NULL DEFAULT 0,
		rx_queue INTEGER NOT NULL DEFAULT 0,
		inode INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		closed_at INTEGER
	)`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixMilli()
	_, err = db.Exec(`
		INSERT INTO connections
			(pid, uid, comm, cmdline, exe, ppid, pcomm, local_addr, local_port, remote_addr, remote_port, protocol, state, tx_queue, rx_queue, inode, created_at, updated_at, closed_at)
		VALUES
			(1, 0, 'open', 'open', '/bin/open', 0, '', '10.0.0.5', 11111, '8.8.8.8', 443, 'tcp', 'ESTABLISHED', 0, 0, 1, ?, ?, NULL),
			(2, 0, 'closed', 'closed', '/bin/closed', 0, '', '10.0.0.5', 11112, '1.1.1.1', 80, 'tcp', 'ESTABLISHED', 0, 0, 2, ?, ?, ?),
			(3, 0, 'other', 'other', '/bin/other', 0, '', '10.0.0.5', 11113, '8.8.8.8', 443, 'tcp', 'ESTABLISHED', 0, 0, 3, ?, ?, NULL)
	`, now-1000, now, now-1000, now, now, now-1000, now)
	if err != nil {
		t.Fatal(err)
	}

	s := &Scheduler{db: db}
	data := s.collect()

	if data.ActiveConns != 2 {
		t.Fatalf("expected 2 open connections, got %d", data.ActiveConns)
	}
	if len(data.TopPorts) == 0 {
		t.Fatal("expected top ports data")
	}
	if data.TopPorts[0].Port != 443 || data.TopPorts[0].Count != 2 {
		t.Fatalf("expected port 443 with count 2, got %+v", data.TopPorts[0])
	}
}
