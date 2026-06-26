package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// RateLimiter provides per-IP request rate limiting using a token bucket approach.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	rate     int           // requests per window
	window   time.Duration // time window
	cleanup  time.Duration // how often to clean stale entries
}

type tokenBucket struct {
	tokens    int
	lastCheck time.Time
}

// NewRateLimiter creates a rate limiter with the given rate (requests per window).
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*tokenBucket),
		rate:     rate,
		window:   window,
		cleanup:  5 * time.Minute,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow checks if a request from the given IP is allowed.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.buckets[ip]
	if !exists {
		rl.buckets[ip] = &tokenBucket{
			tokens:    rl.rate - 1,
			lastCheck: time.Now(),
		}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := time.Since(b.lastCheck)
	b.tokens += int(elapsed / (rl.window / time.Duration(rl.rate)))
	if b.tokens > rl.rate {
		b.tokens = rl.rate
	}
	b.lastCheck = time.Now()

	if b.tokens > 0 {
		b.tokens--
		return true
	}
	return false
}

// Middleware returns an HTTP middleware that rate-limits requests.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !rl.Allow(ip) {
			slog.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
			http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32005,"message":"rate limit exceeded"},"id":null}`, 429)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (for proxied requests)
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Strip port
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == ':' {
			return ip[:i]
		}
	}
	return ip
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, b := range rl.buckets {
			if now.Sub(b.lastCheck) > 10*rl.window {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// ── Structured Logging Setup ──

// SetupLogger configures structured JSON logging.
func SetupLogger() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	handler := slog.NewJSONHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}

// LogNodeStart logs node startup info in structured format.
func LogNodeStart(version, dataDir, dbPath string, height uint64) {
	slog.Info("node starting",
		"version", version,
		"data_dir", dataDir,
		"database", dbPath,
		"height", height,
	)
}

// LogBlock logs a new block being produced.
func LogBlock(height uint64, proposer string, txCount int, accounts int, bps float64) {
	slog.Info("block produced",
		"height", height,
		"proposer", proposer,
		"tx_count", txCount,
		"accounts", accounts,
		"blocks_per_sec", fmt.Sprintf("%.1f", bps),
	)
}

// LogTxSubmission logs a new transaction submission.
func LogTxSubmission(hash string, from string, poolSize int) {
	slog.Info("tx submitted",
		"hash", hash[:16]+"...",
		"from", from[:16]+"...",
		"pool_size", poolSize,
	)
}

// LogSubscription logs a new WebSocket subscription.
func LogSubscription(subID, subType string, wsActive int) {
	slog.Info("ws subscription",
		"subscription_id", subID,
		"type", subType,
		"active_subs", wsActive,
	)
}