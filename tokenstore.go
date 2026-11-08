package catzprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StoredToken is what the SDK keeps in a TokenStore for one device: its
// local token and the last station endpoint list from the cloud, so a hub
// that restarts while the internet is down can still find and trust its
// stations.
type StoredToken struct {
	// Token is the local token ("czl1…"); empty when only endpoints are
	// stored (e.g. with a static LocalConfig.Token).
	Token     string    `json:"token,omitempty"`
	TokenID   string    `json:"token_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// Stations is the last endpoint list from the cloud.
	Stations          []LocalEndpoint `json:"stations,omitempty"`
	StationsUpdatedAt time.Time       `json:"stations_updated_at,omitempty"`
	// LastRemintAt is when a station's token_expired last caused a re-mint
	// (at most once per 10 minutes).
	LastRemintAt time.Time `json:"last_remint_at,omitempty"`
	// IssuedAt is when the token was minted (for the refresh threshold).
	IssuedAt time.Time `json:"issued_at,omitempty"`
}

// String never reveals the token (also used by %v and %+v).
func (t StoredToken) String() string {
	return fmt.Sprintf("catzprint.StoredToken{Token: %q, TokenID: %q, ExpiresAt: %s, Stations: %d}", redactToken(t.Token), t.TokenID, t.ExpiresAt.Format(time.RFC3339), len(t.Stations))
}

// GoString never reveals the token (%#v).
func (t StoredToken) GoString() string { return t.String() }

// Format prints the redacted form for every verb.
func (t StoredToken) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }

// LogValue keeps the token out of log/slog output.
func (t StoredToken) LogValue() slog.Value { return slog.StringValue(t.String()) }

// storedTokenDisk is the form the file store writes.
type storedTokenDisk StoredToken

// EncodeStoredToken is the JSON a TokenStore persists (the same as
// json.Marshal of a StoredToken: the token is included).
func EncodeStoredToken(t *StoredToken) ([]byte, error) { return json.Marshal((*storedTokenDisk)(t)) }

// DecodeStoredToken reads what EncodeStoredToken wrote.
func DecodeStoredToken(b []byte) (*StoredToken, error) {
	var d storedTokenDisk
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	t := StoredToken(d)
	return &t, nil
}

// ErrInsecureTokenStore means the token store file or its directory is not
// owned by the current user or is writable by others. The SDK refuses to use
// it (POSIX only).
var ErrInsecureTokenStore = errors.New("catzprint: insecure token store")

func (t *StoredToken) clone() *StoredToken {
	if t == nil {
		return nil
	}
	cp := *t
	cp.Stations = append([]LocalEndpoint(nil), t.Stations...)
	return &cp
}

// TokenStore persists local tokens between runs. Implementations must be
// safe for concurrent use. Load returns (nil, nil) when nothing is stored
// under key. Keys are opaque strings chosen by the SDK (they never contain
// the API key itself).
type TokenStore interface {
	Load(ctx context.Context, key string) (*StoredToken, error)
	Save(ctx context.Context, key string, tok *StoredToken) error
}

// MemoryTokenStore keeps tokens in memory (the default). Tokens are minted
// again after a restart.
type MemoryTokenStore struct {
	mu sync.Mutex
	m  map[string]*StoredToken
}

// NewMemoryTokenStore returns an empty in-memory store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{m: map[string]*StoredToken{}}
}

// Load implements TokenStore.
func (s *MemoryTokenStore) Load(_ context.Context, key string) (*StoredToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key].clone(), nil
}

// Save implements TokenStore.
func (s *MemoryTokenStore) Save(_ context.Context, key string, tok *StoredToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]*StoredToken{}
	}
	s.m[key] = tok.clone()
	return nil
}

// FileTokenStore keeps tokens in a JSON file readable only by the current
// user (mode 0600; the directory is created with 0700). Every save writes a
// temporary file next to it and renames it into place, so the file is never
// half-written. One file can hold several keys.
type FileTokenStore struct {
	path string
	mu   sync.Mutex
}

// NewFileTokenStore returns a store backed by the file at path.
func NewFileTokenStore(path string) *FileTokenStore { return &FileTokenStore{path: path} }

// Path is the file the store uses.
func (s *FileTokenStore) Path() string { return s.path }

func (s *FileTokenStore) readAll() (map[string]*StoredToken, error) {
	if err := checkStorePerms(filepath.Dir(s.path)); err != nil {
		return nil, err
	}
	if err := checkStorePerms(s.path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]*StoredToken{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("catzprint: reading token store: %w", err)
	}
	disk := map[string]*storedTokenDisk{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &disk); err != nil {
			return nil, fmt.Errorf("catzprint: token store %s is corrupt: %w", s.path, err)
		}
	}
	m := make(map[string]*StoredToken, len(disk))
	for k, v := range disk {
		m[k] = (*StoredToken)(v)
	}
	return m, nil
}

// Load implements TokenStore.
func (s *FileTokenStore) Load(_ context.Context, key string) (*StoredToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readAll()
	if err != nil {
		return nil, err
	}
	return m[key], nil
}

// Save implements TokenStore.
func (s *FileTokenStore) Save(_ context.Context, key string, tok *StoredToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readAll()
	if errors.Is(err, ErrInsecureTokenStore) {
		return err
	}
	if err != nil {
		// A corrupt file is replaced rather than blocking printing.
		m = map[string]*StoredToken{}
	}
	if tok == nil {
		delete(m, key)
	} else {
		m[key] = tok
	}
	disk := make(map[string]*storedTokenDisk, len(m))
	for k, v := range m {
		disk[k] = (*storedTokenDisk)(v)
	}
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("catzprint: encoding token store: %w", err)
	}
	return writeFileAtomic(s.path, b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("catzprint: creating token store directory: %w", err)
	}
	if err := checkStorePerms(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("catzprint: writing token store: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return fmt.Errorf("catzprint: writing token store: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("catzprint: writing token store: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("catzprint: writing token store: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("catzprint: writing token store: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("catzprint: writing token store: %w", err)
	}
	ok = true
	return nil
}
