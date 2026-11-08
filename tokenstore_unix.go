//go:build !windows

package catzprint

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkStorePerms refuses an existing token store file or directory that
// isn't owned by the current (effective) user or is group/world-writable.
func checkStorePerms(path string) error {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("catzprint: checking token store %s: %w", path, err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by another user (uid %d)", ErrInsecureTokenStore, path, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others (mode %v)", ErrInsecureTokenStore, path, fi.Mode().Perm())
	}
	return nil
}
