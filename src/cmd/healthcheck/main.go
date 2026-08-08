// Command healthcheck is a temporary verification harness: it opens the
// database and lets the session health checker run so stale sessions get
// marked dead, then prints the resulting session statuses.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/server"
)

func main() {
	dataDir := "bin/data"
	if len(os.Args) > 1 {
		dataDir = os.Args[1]
	}

	database, err := db.Open(dataDir)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	srv, err := server.New(database, nil)
	if err != nil {
		log.Fatalf("new server: %v", err)
	}

	fmt.Println("== before ==")
	dumpSessions(database.DB())

	if err := srv.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}

	// The health check ticks every 10s; wait past two ticks
	time.Sleep(23 * time.Second)

	fmt.Println("== after ==")
	dumpSessions(database.DB())
}

func dumpSessions(sqlDB *sql.DB) {
	rows, err := sqlDB.Query(`SELECT id, hostname, sleep_interval, last_seen, status FROM sessions ORDER BY last_seen`)
	if err != nil {
		log.Fatalf("query: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, hostname, lastSeen, status string
		var sleep int
		if err := rows.Scan(&id, &hostname, &sleep, &lastSeen, &status); err != nil {
			log.Fatalf("scan: %v", err)
		}
		fmt.Printf("  %s  %s  sleep=%dms  last=%s  status=%s\n", id, hostname, sleep, lastSeen, status)
	}
}
