//go:build !windows

// Package sysproxy is a no-op on non-Windows platforms.
package sysproxy

// DefaultBackupPath returns an empty path on non-Windows platforms.
func DefaultBackupPath() string { return "" }

// Supported reports whether automatic system proxy configuration is available.
func Supported() bool { return false }

// Configure is a no-op on non-Windows platforms.
func Configure(socksAddr string) (func() error, error) {
	return func() error { return nil }, nil
}

// ConfigureWithBackup is a no-op on non-Windows platforms.
func ConfigureWithBackup(socksAddr, backupPath string) (func() error, error) {
	return func() error { return nil }, nil
}
