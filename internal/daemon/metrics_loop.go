package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"backupswarm/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// defaultMetricsShutdownTimeout caps the graceful drain when the daemon stops.
const defaultMetricsShutdownTimeout = 2 * time.Second

// metricsLoopOptions configures runMetricsLoop.
type metricsLoopOptions struct {
	listener        net.Listener
	prom            *metrics.Prom
	shutdownTimeout time.Duration
}

// runMetricsLoop serves /metrics from listener using the prom registry,
// and gracefully drains on ctx cancel. A nil listener or nil prom blocks
// until ctx.Done so the caller can spawn the goroutine unconditionally.
func runMetricsLoop(ctx context.Context, opts metricsLoopOptions) {
	if opts.listener == nil || opts.prom == nil {
		<-ctx.Done()
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(opts.prom.Registry(), promhttp.HandlerOpts{}))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	addr := opts.listener.Addr().String()
	slog.InfoContext(ctx, "metrics endpoint listening", "addr", addr)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(opts.listener)
	}()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.WarnContext(ctx, "metrics server exited", "err", err)
		}
		return
	}

	timeout := opts.shutdownTimeout
	if timeout <= 0 {
		timeout = defaultMetricsShutdownTimeout
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.WarnContext(ctx, "metrics server shutdown", "err", err)
	}
	<-serveErr
}
