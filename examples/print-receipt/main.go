// Command print-receipt prints a small receipt with ESC/POS commands.
//
//	CATZPRINT_API_KEY=cz_test_... go run ./examples/print-receipt
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	catzprint "github.com/Catalizo/catzprint-go/v2"
)

func main() {
	client, err := catzprint.NewClient() // reads CATZPRINT_API_KEY
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	receipt := []catzprint.Command{
		{Type: "text", Text: "Corner Café", Align: "center", Bold: true, Size: 2},
		{Type: "text", Text: "Order #1042", Align: "center"},
		catzprint.Line(),
		catzprint.Columns(catzprint.Column{Text: "2 x Flat white"}, catzprint.Column{Text: "7.00", Align: "right"}),
		catzprint.Columns(catzprint.Column{Text: "1 x Croissant"}, catzprint.Column{Text: "3.20", Align: "right"}),
		catzprint.Line(),
		catzprint.Columns(catzprint.Column{Text: "Total", Bold: true}, catzprint.Column{Text: "10.20", Align: "right", Bold: true}),
		catzprint.Feed(1),
		catzprint.QR("https://example.com/r/1042"),
		{Type: "text", Text: "Thank you!", Align: "center"},
		{Type: "cut", Partial: true},
	}
	job, err := client.PrintReceipt(ctx, receipt, catzprint.JobParams{
		Role:           "receipt",
		Reference:      "order-1042",
		IdempotencyKey: "order-1042", // retrying never prints twice
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Job %s is %s (billed as %s)\n", job.ID, job.Status, job.BilledAs)
}
