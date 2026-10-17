package catzprint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"golang.org/x/crypto/nacl/box"
)

// ServerKey returns the server's X25519 public key for sealed printing
// (GET /v1/public/server-key). It is fetched once and cached.
func (c *Client) ServerKey(ctx context.Context) (*[32]byte, error) {
	c.mu.Lock()
	k := c.serverKey
	c.mu.Unlock()
	if k != nil {
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
	if err != nil || len(raw) != 32 || bytes.Equal(raw, make([]byte, 32)) {
		return nil, &APIError{Status: http.StatusOK, Code: "invalid_response", Message: "The server key isn't a 32-byte base64 X25519 key."}
	}
	k = new([32]byte)
	copy(k[:], raw)
	c.mu.Lock()
	c.serverKey = k
	c.mu.Unlock()
	return k, nil
}

// Seal encrypts msg to an X25519 public key with a NaCl sealed box
// (crypto_box_seal), compatible with libsodium, PyNaCl and the server.
func Seal(publicKey *[32]byte, msg []byte) ([]byte, error) { return sealTo(publicKey, msg) }

func sealTo(pub *[32]byte, msg []byte) ([]byte, error) {
	out, err := box.SealAnonymous(nil, msg, pub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("catzprint: sealing content: %w", err)
	}
	return out, nil
}
