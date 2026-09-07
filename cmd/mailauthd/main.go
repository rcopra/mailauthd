// Command mailauthd runs the mailauth HTTP service.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("MAILAUTHD_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	http.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		// TODO(M2): bounded-semaphore backpressure + verdict pipeline.
		respondWithError(w, http.StatusNotImplemented, "not implemented")
	})
	log.Printf("mailauthd listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// respondWithJSON writes payload as a JSON response.
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
	return nil
}

// respondWithError writes a JSON error response {"error": msg}.
func respondWithError(w http.ResponseWriter, code int, msg string) error {
	return respondWithJSON(w, code, map[string]string{"error": msg})
}
