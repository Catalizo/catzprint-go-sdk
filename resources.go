package catzprint

import (
	"context"
	"net/http"
)

// PrintersService lists printers. Use it via Client.Printers.
type PrintersService struct{ c *Client }

// List returns the organization's printers.
func (s *PrintersService) List(ctx context.Context) ([]Printer, error) {
	path, err := s.c.orgPath(ctx, "/printers")
	if err != nil {
		return nil, err
	}
	var out struct {
		Printers []Printer `json:"printers"`
	}
	if err := s.c.do(ctx, http.MethodGet, path, nil, nil, &out, false); err != nil {
		return nil, err
	}
	return out.Printers, nil
}

// LocationsService lists and reads locations. Use it via Client.Locations.
type LocationsService struct{ c *Client }

// List returns the organization's locations.
func (s *LocationsService) List(ctx context.Context) ([]Location, error) {
	path, err := s.c.orgPath(ctx, "/locations")
	if err != nil {
		return nil, err
	}
	var out struct {
		Locations []Location `json:"locations"`
	}
	if err := s.c.do(ctx, http.MethodGet, path, nil, nil, &out, false); err != nil {
		return nil, err
	}
	return out.Locations, nil
}

// Get returns one location.
func (s *LocationsService) Get(ctx context.Context, id string) (*Location, error) {
	path, err := s.c.orgPath(ctx, "/locations/%s", id)
	if err != nil {
		return nil, err
	}
	var out struct {
		Location *Location `json:"location"`
	}
	if err := s.c.do(ctx, http.MethodGet, path, nil, nil, &out, false); err != nil {
		return nil, err
	}
	return out.Location, nil
}

// TemplatesService lists receipt templates. Use it via Client.Templates.
type TemplatesService struct{ c *Client }

// List returns the organization's templates (needs the jobs:write scope).
func (s *TemplatesService) List(ctx context.Context) ([]Template, error) {
	path, err := s.c.orgPath(ctx, "/templates")
	if err != nil {
		return nil, err
	}
	var out struct {
		Templates []Template `json:"templates"`
	}
	if err := s.c.do(ctx, http.MethodGet, path, nil, nil, &out, false); err != nil {
		return nil, err
	}
	return out.Templates, nil
}
