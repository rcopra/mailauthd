// Command mailauthd runs the mailauth HTTP service.
package main

import (
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
		http.Error(w, "not implemented", http.StatusNotImplemented)
	})
	log.Printf("mailauthd listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
