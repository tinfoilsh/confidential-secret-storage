package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tinfoilsh/confidential-secret-storage/internal/server"
	"github.com/tinfoilsh/confidential-secret-storage/internal/store"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

// gitSHA is injected at build time via -ldflags="-X main.gitSHA=...".
var gitSHA = "unknown"

func main() {
	addr := envDefault("LISTEN_ADDR", ":8089")
	if env := os.Getenv("GIT_SHA"); env != "" {
		gitSHA = env
	}

	// v0: in-enclave AES-GCM store (ephemeral, in-memory).
	// v1 will swap to a buckets-sidecar backed store.
	bucketStore := store.NewInEnclaveStore()

	// Attestation config for /pull verification.
	// ALLOWED_REPOS is a comma-separated list of GitHub repos (owner/name)
	// whose published Sigstore attestation measurements are accepted.
	// DEV_SKIP_CODE_MEASUREMENT=true skips the Sigstore check (dev only);
	// SNP/TDX quote verification and TLS-key binding are still enforced.
	var attCfg *server.AttestationConfig
	allowedRepos := splitEnv("ALLOWED_REPOS")
	devSkip := os.Getenv("DEV_SKIP_CODE_MEASUREMENT") == "true"

	if len(allowedRepos) > 0 || devSkip {
		attCfg = &server.AttestationConfig{
			AllowedRepos:           allowedRepos,
			DevSkipCodeMeasurement: devSkip,
		}
		if !devSkip {
			sigClient, err := sigstore.NewClient()
			if err != nil {
				log.Printf("Warning: sigstore client init failed: %v", err)
			} else {
				attCfg.SigClient = sigClient
				log.Println("Sigstore client initialized for code-measurement verification")
			}
		}
		log.Printf("Attested-client verification enabled: allowed-repos=%v dev-skip=%v", allowedRepos, devSkip)
	} else {
		log.Println("Warning: /pull attestation verification disabled (set ALLOWED_REPOS or DEV_SKIP_CODE_MEASUREMENT)")
	}

	srv := server.New(bucketStore, attCfg)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go func() {
		log.Printf("confidential-secret-storage listening on %s (git=%s)", addr, gitSHA)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutdown signal received")

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer sCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitEnv(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
