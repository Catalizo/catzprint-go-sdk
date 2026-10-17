// Command print-pdf-and-wait prints a PDF, sealed end to end, and waits
// until the station reports it printed.
//
//	CATZPRINT_API_KEY=cz_live_... go run ./examples/print-pdf-and-wait invoice.pdf
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	catzprint "github.com/Catalizo/catzprint-go/v2"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: print-pdf-and-wait <file.pdf> [printer-id]")
	}
	client, err := catzprint.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	params := catzprint.JobParams{Role: "office", Sealed: true}
	if len(os.Args) > 2 {
		params.PrinterID = os.Args[2]
	}
	job, err := client.PrintFile(ctx, os.Args[1], params)
	var oop *catzprint.OutOfPrintsError
	switch {
	case errors.As(err, &oop):
		log.Fatal("Out of prints: ", oop.Message)
	case err != nil:
		log.Fatal(err)
	}
	fmt.Printf("Sent job %s to %s, waiting…\n", job.ID, deref(job.PrinterName))

	job, err = client.Jobs.WaitFor(ctx, job.ID, catzprint.WithWaitTimeout(2*time.Minute))
	var te *catzprint.TimeoutError
	if errors.As(err, &te) {
		log.Fatalf("Still %s after 2 minutes; is the station online?", te.Job.Status)
	} else if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Job %s finished: %s %s\n", job.ID, job.Status, job.StatusDetail)
}

func deref(s *string) string {
	if s == nil {
		return "the best printer"
	}
	return *s
}
