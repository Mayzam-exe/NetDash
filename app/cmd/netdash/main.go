package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"netdash/internal/api"
	"netdash/internal/engine"
	"netdash/internal/store"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7420", "listen address")
	dataDir := flag.String("data", "", "data directory (default: platform user data dir)")
	authToken := flag.String("auth-token", "", "require this bearer token on /api/* (env NETDASH_AUTH_TOKEN); empty = no auth")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("netdash", engine.Version)
		return
	}
	if *authToken == "" {
		*authToken = os.Getenv("NETDASH_AUTH_TOKEN")
	}

	dir := *dataDir
	if dir == "" {
		dir = defaultDataDir()
	}

	st, err := store.Open(dir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	hub := engine.NewHub()
	eng, err := engine.New(st, hub)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go eng.Run(ctx)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.New(eng, *authToken).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		// A global write cap bounds every handler; the SSE stream
		// (/api/stream) clears its own deadline so it is not cut off.
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(shutCtx)
	}()

	fmt.Printf("NetDash %s\n  UI:  http://%s\n  Data: %s\n", engine.Version, *addr, dir)
	warnIfExposed(*addr, *authToken)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	eng.Shutdown() // repair poisoned ARP caches so blocked devices reconnect
}

// warnIfExposed prints a loud warning when the API is bound to a non-loopback
// address without an auth token: that exposes device control (and settings,
// including the SNMP community) to anyone on the network.
func warnIfExposed(addr, token string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	loopback := host == "" || host == "localhost"
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	if !loopback && token == "" {
		log.Printf("WARNING: listening on %s without -auth-token — anyone on the "+
			"network can read settings (incl. the SNMP community) and block or "+
			"limit devices. Set -auth-token or NETDASH_AUTH_TOKEN.", addr)
	}
}

func defaultDataDir() string {
	if v := os.Getenv("NETDASH_DATA"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("APPDATA"); base != "" {
			return filepath.Join(base, "netdash")
		}
		return `C:\ProgramData\netdash`
	}
	if base := os.Getenv("XDG_DATA_HOME"); base != "" {
		return filepath.Join(base, "netdash")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./netdash-data"
	}
	return filepath.Join(home, ".local", "share", "netdash")
}
