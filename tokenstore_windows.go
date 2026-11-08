//go:build windows

package catzprint

// checkStorePerms is a no-op on Windows (ACLs, not POSIX modes).
func checkStorePerms(string) error { return nil }
