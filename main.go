package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shhx.dev/internal/app"
)

var buildVersion = "dev"

const (
	// defaultAddr is the listen address used when ADDR is unset.
	defaultAddr = ":8194"
	// addrEnv is the environment variable that overrides the listen address.
	addrEnv = "ADDR"

	// readHeaderTimeout bounds how long request headers may take to arrive.
	readHeaderTimeout = 5 * time.Second
	// readTimeout bounds the full request read for non-streaming routes.
	readTimeout = 10 * time.Second
	// writeTimeout bounds writes for non-streaming routes. SSE handlers clear
	// this per-connection via http.ResponseController so long-lived event
	// streams are not severed mid-flight.
	writeTimeout = 30 * time.Second
	// idleTimeout bounds keep-alive idle time between requests.
	idleTimeout = 60 * time.Second
	// maxHeaderBytes caps request header size to fail fast on abuse.
	maxHeaderBytes = 8 << 10
	// shutdownTimeout bounds graceful shutdown before forced close.
	shutdownTimeout = 10 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run wires signals, starts the HTTP server, and returns a process exit code.
// It keeps os.Exit and signal handling at the process boundary so the rest of
// the program stays testable and library-friendly.
func run(_ []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := os.Getenv(addrEnv)
	if addr == "" {
		addr = defaultAddr
	}

	server, err := app.NewServer(buildVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create server: %v\n", err)
		return 1
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	serveErr := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "shhx listening on %s\n", addr)
		serveErr <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "listen: %v\n", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		stop() // restore default signal handling so a second signal force-quits
		fmt.Fprintln(os.Stderr, "shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "shutdown: %v\n", err)
			return 1
		}
		return 0
	}
}
