package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tinfoilsh/confidential-secret-storage/internal/server"
	"github.com/tinfoilsh/confidential-secret-storage/internal/store"
)

func main() {
	bucketStore := store.NewInEnclaveStore()

	consumerHost := os.Getenv("CONSUMER_HOST")
	consumerRepo := os.Getenv("CONSUMER_REPO")

	srv := server.New(bucketStore, consumerHost, consumerRepo)

	httpServer := &http.Server{
		Addr:              ":8089",
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go func() {
		log.Printf("confidential-secret-storage listening on :8089")
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
