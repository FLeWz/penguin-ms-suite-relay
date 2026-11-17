// Command relay turns Microsoft Graph change notifications into a WebSocket
// push channel. See README.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	st, err := newStore(env("RELAY_STATE_FILE", "/data/devices.json"), 10000)
	if err != nil {
		log.Fatalf("state: %v", err)
	}
	trust, _ := strconv.ParseBool(env("RELAY_TRUST_PROXY", "false"))
	invite := os.Getenv("RELAY_INVITE_SECRET")
	if invite == "" {
		log.Printf("warning: RELAY_INVITE_SECRET empty, /register is open")
	}
	srv := newServer(st, invite, trust)

	hs := &http.Server{
		Addr:              env("RELAY_ADDR", ":8090"),
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second, // does not affect hijacked WebSockets
	}
	go func() {
		log.Printf("listening on %s", hs.Addr)
		if err := hs.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hs.Shutdown(ctx)
}
