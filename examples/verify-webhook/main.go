// Command verify-webhook serves a net/http endpoint that verifies CatzPrint
// webhooks.
//
//	CATZPRINT_WEBHOOK_SECRET=whsec_... go run ./examples/verify-webhook
package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"os"

	catzprint "github.com/Catalizo/catzprint-go/v2"
)

func main() {
	secret := os.Getenv("CATZPRINT_WEBHOOK_SECRET")
	if secret == "" {
		log.Fatal("set CATZPRINT_WEBHOOK_SECRET")
	}
	http.HandleFunc("POST /webhooks/catzprint", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // the raw bytes, unparsed
		if err != nil {
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}
		event, err := catzprint.VerifyWebhook(body, r.Header.Get(catzprint.SignatureHeader), secret)
		var sigErr *catzprint.SignatureVerificationError
		if errors.As(err, &sigErr) {
			log.Printf("rejected webhook: %s", sigErr.Reason)
		}
		if err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}
		switch event.Type {
		case "job.printed", "job.failed":
			job, err := event.Job()
			if err == nil && job != nil {
				log.Printf("job %s (%s) is %s", job.ID, job.Reference, job.Status)
			}
		default:
			log.Printf("event %s", event.Type)
		}
		w.WriteHeader(http.StatusNoContent) // answer 2xx quickly
	})
	log.Println("listening on :4242")
	log.Fatal(http.ListenAndServe(":4242", nil))
}
