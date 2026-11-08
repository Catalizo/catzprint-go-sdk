package catzprint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// serverKeyTTL is how long a fetched server key is used before it is
// fetched again (the server may rotate it).
const serverKeyTTL = time.Hour

// ServerKey returns the server's X25519 public key for sealed printing
// (GET /v1/public/server-key). It is cached for an hour, and dropped at once
// when the API can't decrypt a sealed job (the key was rotated).
func (c *Client) ServerKey(ctx context.Context) (*[32]byte, error) {
	c.mu.Lock()
	k, at, gen := c.serverKey, c.serverKeyAt, c.serverKeyGen
	c.mu.Unlock()
	if k != nil && time.Since(at) < serverKeyTTL {
		return k, nil
	}
	var out struct {
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/public/server-key", nil, nil, &out, false); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(out.PublicKey)
	if err != nil || len(raw) != 32 || bytes.Equal(raw, make([]byte, 32)) || checkX25519Key(raw) != nil {
		return nil, &APIError{Status: http.StatusOK, Code: "invalid_response", Message: "The server key isn't a 32-byte base64 X25519 key."}
	}
	k = new([32]byte)
	copy(k[:], raw)
	c.mu.Lock()
	if c.serverKeyGen == gen {
		// Only the newest fetch installs its key: a fetch that started
		// before a dropServerKey must not bring the dropped key back.
		c.serverKey, c.serverKeyAt = k, time.Now()
	}
	c.mu.Unlock()
	return k, nil
}

// dropServerKey forgets the cached server key, so the next sealed job
// fetches it again.
func (c *Client) dropServerKey() {
	c.mu.Lock()
	c.serverKey, c.serverKeyAt = nil, time.Time{}
	c.serverKeyGen++
	c.mu.Unlock()
}

// Seal encrypts msg to an X25519 public key with a NaCl sealed box
// (crypto_box_seal), compatible with libsodium, PyNaCl and the server.
func Seal(publicKey *[32]byte, msg []byte) ([]byte, error) { return sealTo(publicKey, msg) }

// checkX25519Key rejects small-order public keys: with them the shared
// secret is all zeros (curve25519.X25519 reports that as an error) and the
// "sealed" box could be opened by anyone.
func checkX25519Key(pub []byte) error {
	var scalar [32]byte
	if _, err := rand.Read(scalar[:]); err != nil {
		return err
	}
	if _, err := curve25519.X25519(scalar[:], pub); err != nil {
		return errors.New("catzprint: the public key is a small-order X25519 point; refusing to seal to it")
	}
	return nil
}

func sealTo(pub *[32]byte, msg []byte) ([]byte, error) {
	if err := checkX25519Key(pub[:]); err != nil {
		return nil, err
	}
	out, err := box.SealAnonymous(nil, msg, pub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("catzprint: sealing content: %w", err)
	}
	return out, nil
}
