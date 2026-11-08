// Command local-hub is a restaurant hub that keeps printing kitchen tickets
// when the internet is down, through the CatzPrint station on the same
// network (local_first mode).
//
//	CATZPRINT_API_KEY=cz_live_... CATZPRINT_LOCATION_ID=... go run ./examples/local-hub
//
// Run it once while online: the SDK mints a local token and saves it, with
// the stations' addresses and certificate fingerprints, in
// ~/.catzprint/local-tokens.json. From then on tickets print through the
// station even after a restart without internet.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	catzprint "github.com/Catalizo/catzprint-go-sdk/v2"
)

type item struct {
	Qty  int
	Name string
	Note string
}

type order struct {
	ID        int
	Table     string
	Items     []item
	Allergies []string
}

func main() {
	home, _ := os.UserHomeDir()
	client, err := catzprint.NewClient(
		catzprint.WithLocal(catzprint.LocalConfig{
			Mode:       catzprint.ModeLocalFirst,
			LocationID: os.Getenv("CATZPRINT_LOCATION_ID"),
			Discover:   true, // cloud endpoint list + mDNS
			TokenStore: catzprint.NewFileTokenStore(filepath.Join(home, ".catzprint", "local-tokens.json")),
			DeviceName: "Hub (front counter)",
			Wait:       5 * time.Second, // answer once the ticket printed
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if st, err := client.Local.Status(ctx); err == nil {
		fmt.Printf("Station %s: cloud connected %v, %d jobs to sync, %d offline prints left\n",
			st.Station.Name, st.Station.CloudConnected, st.Unsynced, st.Allowance.PrintsLeft)
	}

	o := order{ID: 1042, Table: "12", Items: []item{{2, "Pad thai", "no egg"}, {1, "Green curry", ""}}, Allergies: []string{"PEANUTS"}}
	job, err := printKitchenTicket(ctx, client, o)
	switch {
	case err == nil:
		fmt.Printf("Ticket %s %s via %s\n", job.ID, job.Status, job.Via)
	case catzprint.IsPrinterOffline(err), catzprint.IsOutOfPaper(err):
		// The station refused before printing: tell the staff, then retry
		// with the same order (the same idempotency key never prints twice).
		log.Fatalf("Kitchen printer needs attention: %v", err)
	case catzprint.IsStationUnreachable(err):
		var sue *catzprint.StationUnreachableError
		errors.As(err, &sue)
		log.Fatalf("No station and no internet (tried %v): %v", sue.URLs(), err)
	default:
		log.Fatal(err)
	}
}

// printKitchenTicket prints one order's kitchen ticket. Orders with
// allergies get a ticket built from commands with an inverted ALLERGY
// banner; the rest use the saved "kitchen" template.
func printKitchenTicket(ctx context.Context, client *catzprint.Client, o order) (*catzprint.Job, error) {
	params := catzprint.JobParams{
		Role:      "kitchen",
		Title:     fmt.Sprintf("Table %s", o.Table),
		Reference: fmt.Sprintf("order-%d", o.ID),
		// Bump r1 → r2 only for a deliberate reprint.
		IdempotencyKey: fmt.Sprintf("order-%d-kitchen-r1", o.ID),
	}
	if len(o.Allergies) > 0 {
		cmds := []catzprint.Command{
			{Type: "text", Text: " ALLERGY: " + strings.Join(o.Allergies, ", ") + " ", Align: "center", Bold: true, Invert: true, Size: 2},
			catzprint.Feed(1),
			{Type: "text", Text: "Table " + o.Table, Bold: true, Size: 2},
			catzprint.Line(),
		}
		for _, it := range o.Items {
			cmds = append(cmds, catzprint.Columns(catzprint.Column{Text: fmt.Sprintf("%d x", it.Qty), Width: 0.15}, catzprint.Column{Text: it.Name, Bold: true}))
			if it.Note != "" {
				cmds = append(cmds, catzprint.Text("   "+it.Note))
			}
		}
		cmds = append(cmds, catzprint.Line(),
			catzprint.Command{Type: "text", Text: " ALLERGY: " + strings.Join(o.Allergies, ", ") + " ", Align: "center", Bold: true, Invert: true},
			catzprint.Feed(2), catzprint.Cut())
		params.Commands = cmds
	} else {
		items := make([]map[string]any, len(o.Items))
		for i, it := range o.Items {
			items[i] = map[string]any{"qty": it.Qty, "name": it.Name, "note": it.Note}
		}
		params.TemplateID = os.Getenv("CATZPRINT_KITCHEN_TEMPLATE_ID")
		params.Data = map[string]any{"order": o.ID, "table": o.Table, "items": items}
	}
	return client.Jobs.Create(ctx, params)
}
