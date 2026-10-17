package catzprint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestSealOpensWithNaCl(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("%PDF-1.4 sealed hello")
	sealed, err := Seal(pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != len(msg)+box.AnonymousOverhead {
		t.Fatalf("sealed length %d", len(sealed))
	}
	got, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	if !ok || !bytes.Equal(got, msg) {
		t.Fatal("round trip failed")
	}
	again, _ := Seal(pub, msg)
	if bytes.Equal(again, sealed) {
		t.Fatal("sealing must use a fresh ephemeral key each time")
	}
}

// TestSealOpensWithLibsodium proves wire compatibility with libsodium's
// crypto_box_seal_open through PyNaCl (skipped when it isn't installed).
func TestSealOpensWithLibsodium(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	if exec.Command(py, "-c", "import nacl.public").Run() != nil {
		t.Skip("PyNaCl not installed")
	}
	pub, priv, _ := box.GenerateKey(rand.Reader)
	msg := []byte("Sealed with Go, opened with libsodium ✓")
	sealed, err := Seal(pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	script := `import sys, base64
from nacl.public import PrivateKey, SealedBox
sk = PrivateKey(base64.b64decode(sys.argv[1]))
sys.stdout.write(base64.b64encode(SealedBox(sk).decrypt(base64.b64decode(sys.argv[2]))).decode())`
	out, err := exec.Command(py, "-I", "-c", script, base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(sealed)).Output()
	if err != nil {
		t.Fatalf("libsodium couldn't open it: %v", err)
	}
	got, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q", got)
	}
}

func TestSealedCreateUsesCachedServerKey(t *testing.T) {
	pub, priv, _ := box.GenerateKey(rand.Reader)
	var keyCalls atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/public/server-key" {
			keyCalls.Add(1)
			_, _ = io.WriteString(w, `{"algorithm":"x25519-xsalsa20-poly1305-sealed-box","public_key":"`+base64.StdEncoding.EncodeToString(pub[:])+`"}`)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, has := body["content"]; has {
			t.Error("plain content sent alongside sealed_content")
		}
		raw, _ := base64.StdEncoding.DecodeString(body["sealed_content"].(string))
		plain, ok := box.OpenAnonymous(nil, raw, pub, priv)
		if !ok {
			t.Error("server couldn't open sealed content")
		}
		want := map[string]string{"pdf": "%PDF-1.7 secret", "text": "secret note"}[body["kind"].(string)]
		if string(plain) != want {
			t.Errorf("kind %v plain %q", body["kind"], plain)
		}
		_, _ = io.WriteString(w, `{"job":{"id":"j1"}}`)
	})
	ctx := context.Background()
	if _, err := c.PrintPDF(ctx, []byte("%PDF-1.7 secret"), JobParams{Sealed: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrintText(ctx, "secret note", JobParams{Sealed: true}); err != nil {
		t.Fatal(err)
	}
	if keyCalls.Load() != 1 {
		t.Fatalf("server key fetched %d times", keyCalls.Load())
	}
}
