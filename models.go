package catzprint

import (
	"encoding/json"
	"time"
)

// Job statuses.
const (
	StatusScheduled = "scheduled"
	StatusHeld      = "held"
	StatusQueued    = "queued"
	StatusSent      = "sent"
	StatusPrinting  = "printing"
	StatusPrinted   = "printed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// Key is the identity of the API key in use (GET /v1/key).
type Key struct {
	ID      string   `json:"id"`
	OrgID   string   `json:"org_id"`
	OrgName string   `json:"org_name"`
	Live    bool     `json:"live"`
	Scopes  []string `json:"scopes"`
}

// Job is a print job.
type Job struct {
	ID           string     `json:"id"`
	Live         bool       `json:"live"`
	Source       string     `json:"source"`
	Kind         string     `json:"kind"`
	Status       string     `json:"status"`
	StatusDetail string     `json:"status_detail"`
	Title        string     `json:"title"`
	Reference    string     `json:"reference"`
	Copies       int        `json:"copies"`
	PrinterID    *string    `json:"printer_id"`
	PrinterName  *string    `json:"printer_name"`
	StationID    *string    `json:"station_id"`
	StationName  *string    `json:"station_name"`
	LocationID   *string    `json:"location_id"`
	LocationName *string    `json:"location_name"`
	Size         int64      `json:"size"`
	Attempts     int        `json:"attempts"`
	BilledAs     string     `json:"billed_as"`
	CreatedBy    *string    `json:"created_by"`
	ReprintOf    *string    `json:"reprint_of"`
	ScheduledFor *time.Time `json:"scheduled_for"`
	CreatedAt    time.Time  `json:"created_at"`
	SentAt       *time.Time `json:"sent_at"`
	PrintedAt    *time.Time `json:"printed_at"`
	FinishedAt   *time.Time `json:"finished_at"`

	// PrintedLocally is true when a station printed the job through its
	// local API (directly, or reported later by reconciliation).
	PrintedLocally bool `json:"printed_locally"`
	// LocalDevice is the name of the device that sent a local job.
	LocalDevice *string `json:"local_device"`
	// DuplicateOf is set on a job recorded by reconciliation when another
	// job with the same idempotency key had already printed elsewhere.
	DuplicateOf *string `json:"duplicate_of"`
	// Offline is true in webhook payloads when the station had no cloud
	// connection when it printed.
	Offline bool `json:"offline,omitempty"`
	// IdempotencyKey is the job's idempotency key, when the API or station
	// reports it.
	IdempotencyKey string `json:"idempotency_key,omitempty"`

	// Via is set by the SDK: "local" when a station on the local network
	// took the job, "cloud" when the CatzPrint API did. Jobs.Create and
	// Jobs.Get fill it.
	Via string `json:"via,omitempty"`
	// Local is the station's own view of a local job (Via == "local").
	Local *LocalJob `json:"-"`

	// Events is the job's status history. Only Jobs.Get fills it.
	Events []JobEvent `json:"events,omitempty"`
}

// Finished reports whether the job reached a final status (printed, failed
// or cancelled).
func (j *Job) Finished() bool {
	return j.Status == StatusPrinted || j.Status == StatusFailed || j.Status == StatusCancelled
}

// JobEvent is one entry of a job's history.
type JobEvent struct {
	At     time.Time `json:"at"`
	Status string    `json:"status"`
	Detail string    `json:"detail"`
	Actor  string    `json:"actor"`
}

// Printer is a printer attached to a station.
type Printer struct {
	ID                    string    `json:"id"`
	StationID             string    `json:"station_id"`
	StationName           string    `json:"station_name"`
	LocationID            *string   `json:"location_id"`
	DeviceKey             string    `json:"device_key"`
	Name                  string    `json:"name"`
	Role                  string    `json:"role"`
	Connection            string    `json:"connection"`
	Address               string    `json:"address"`
	Paper                 string    `json:"paper"`
	Capabilities          []string  `json:"capabilities"`
	Enabled               bool      `json:"enabled"`
	Status                string    `json:"status"`
	StatusDetail          string    `json:"status_detail"`
	SharedWithIndividuals bool      `json:"shared_with_individuals"`
	StationEnabled        bool      `json:"station_enabled"`
	StationConnected      bool      `json:"station_connected"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Location is a place with stations (a shop, a kitchen, an office).
type Location struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Address            string     `json:"address"`
	TimeZone           string     `json:"time_zone"`
	Enabled            bool       `json:"enabled"`
	DisabledAt         *time.Time `json:"disabled_at"`
	DisabledJobPolicy  string     `json:"disabled_job_policy"`
	FallbackLocationID *string    `json:"fallback_location_id"`
	Stations           int        `json:"stations"`
	Printers           int        `json:"printers"`
	CreatedAt          time.Time  `json:"created_at"`
}

// Template is a saved receipt layout with {{placeholders}}. Body is the
// template's command list as JSON.
type Template struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Paper     string          `json:"paper"`
	Body      json.RawMessage `json:"body"`
	Version   int             `json:"version"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Command is one ESC/POS receipt command. Set Type and the fields it uses:
//
//	text     Text, Align (left|center|right), Bold, Underline, Invert, Size (1..8), Font (a|b)
//	feed     Lines
//	line     Char
//	columns  Columns
//	barcode  Format, Data
//	qr       Data
//	image    Data (base64 PNG or JPEG), Align
//	cut      Partial
//	drawer   Pin (2 or 5)
//	beep     (no fields)
//	each     Items, Commands (templates only)
type Command struct {
	Type string `json:"type"`

	Text      string `json:"text,omitempty"`
	Align     string `json:"align,omitempty"`
	Bold      bool   `json:"bold,omitempty"`
	Underline bool   `json:"underline,omitempty"`
	Invert    bool   `json:"invert,omitempty"`
	Size      int    `json:"size,omitempty"`
	Font      string `json:"font,omitempty"`

	Lines int    `json:"lines,omitempty"`
	Char  string `json:"char,omitempty"`

	Columns []Column `json:"columns,omitempty"`

	Format string `json:"format,omitempty"`
	Data   string `json:"data,omitempty"`

	Partial bool `json:"partial,omitempty"`
	Pin     int  `json:"pin,omitempty"`

	Items    string    `json:"items,omitempty"`
	Commands []Command `json:"commands,omitempty"`
}

// Column is one cell of a "columns" command.
type Column struct {
	Text  string  `json:"text"`
	Width float64 `json:"width,omitempty"` // fraction of the line; 0 shares what's left
	Align string  `json:"align,omitempty"`
	Bold  bool    `json:"bold,omitempty"`
}

// Command builders for the common cases.

// Text is a "text" command.
func Text(s string) Command { return Command{Type: "text", Text: s} }

// Line is a horizontal rule.
func Line() Command { return Command{Type: "line"} }

// Feed advances the paper n lines.
func Feed(n int) Command { return Command{Type: "feed", Lines: n} }

// Columns is a row of cells.
func Columns(cols ...Column) Command { return Command{Type: "columns", Columns: cols} }

// QR prints a QR code.
func QR(data string) Command { return Command{Type: "qr", Data: data} }

// Cut cuts the paper (fully).
func Cut() Command { return Command{Type: "cut"} }
