// Command mailauthd runs the mailauth HTTP service.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("MAILAUTHD_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		// TODO(M2): bounded-semaphore backpressure + verdict pipeline.
		_ = respondWithError(w, http.StatusNotImplemented, "not implemented")
	})
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           mux,
	}
	// #nosec G706 -- addr comes from operator-provided env, not request data.
	log.Printf("mailauthd listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// A write error after WriteHeader only means the client went away.
	_, _ = w.Write(response)
	return nil
}

func respondWithError(w http.ResponseWriter, code int, msg string) error {
	return respondWithJSON(w, code, map[string]string{"error": msg})
}
