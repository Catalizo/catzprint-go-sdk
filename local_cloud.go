package catzprint

import (
	"context"
	"net/http"
	"net/url"
)

// LocalTokensService mints and revokes local tokens. A local token
// ("czl1…") lets a device print through any station of the organization on
// its local network, verified by the station without the internet. Use it
// via Client.LocalTokens; with WithLocal the SDK mints, caches and refreshes
// tokens for you.
type LocalTokensService struct{ c *Client }

// Create mints a local token (POST /v1/orgs/{org}/local-tokens). It needs
// an API key with the jobs:write scope.
func (s *LocalTokensService) Create(ctx context.Context, params LocalTokenParams) (*LocalToken, error) {
	return s.create(ctx, params, s.c.defaultCallOpts())
}

func (s *LocalTokensService) create(ctx context.Context, params LocalTokenParams, o callOpts) (*LocalToken, error) {
	if params.DeviceName == "" {
		return nil, invalidParams("device_name", "Set DeviceName.")
	}
	if params.TTLDays < 0 || params.TTLDays > 30 {
		return nil, invalidParams("ttl_days", "TTLDays must be between 1 and 30.")
	}
	path, err := s.c.orgPath(ctx, "/local-tokens")
	if err != nil {
		return nil, err
	}
	body := map[string]any{"device_name": params.DeviceName}
	if len(params.LocationIDs) > 0 {
		body["location_ids"] = params.LocationIDs
	}
	if params.TTLDays > 0 {
		body["ttl_days"] = params.TTLDays
	}
	var out LocalToken
	if err := s.c.doWith(ctx, o, http.MethodPost, path, nil, body, &out, false); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, &APIError{Status: http.StatusCreated, Code: "invalid_response", Message: "The API answered without a token."}
	}
	return &out, nil
}

// Revoke revokes a local token by its token ID (the jti). Stations refuse
// it once they have synced their configuration.
func (s *LocalTokensService) Revoke(ctx context.Context, tokenID string) error {
	path, err := s.c.orgPath(ctx, "/local-tokens/%s", tokenID)
	if err != nil {
		return err
	}
	return s.c.do(ctx, http.MethodDelete, path, nil, nil, nil, false)
}

// LocalEndpointsService lists the local-network addresses of the
// organization's stations. Use it via Client.LocalEndpoints.
type LocalEndpointsService struct{ c *Client }

// List returns the stations' local endpoints, optionally only those at one
// location (pass "" for all).
func (s *LocalEndpointsService) List(ctx context.Context, locationID string) ([]LocalEndpoint, error) {
	return s.list(ctx, locationID, s.c.defaultCallOpts())
}

func (s *LocalEndpointsService) list(ctx context.Context, locationID string, o callOpts) ([]LocalEndpoint, error) {
	path, err := s.c.orgPath(ctx, "/local-endpoints")
	if err != nil {
		return nil, err
	}
	var q url.Values
	if locationID != "" {
		q = url.Values{"location_id": {locationID}}
	}
	var out struct {
		Stations []LocalEndpoint `json:"stations"`
	}
	if err := s.c.doWith(ctx, o, http.MethodGet, path, q, nil, &out, false); err != nil {
		return nil, err
	}
	if out.Stations == nil {
		out.Stations = []LocalEndpoint{}
	}
	return out.Stations, nil
}
