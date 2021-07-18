package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"shhx.dev/internal/app"
)

func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8194"
	}

	server, err := app.NewServer()
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	log.Printf("shhx listening on %s", addr)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
