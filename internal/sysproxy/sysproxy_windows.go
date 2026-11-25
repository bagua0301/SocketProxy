//go:build windows

// Package sysproxy configures the Windows system (WinINET) proxy so that
// browsers such as Chrome and Edge automatically use the local HTTP proxy.
package sysproxy

import (
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const regPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const (
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

var (
	wininet                = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

type snapshot struct {
	ProxyEnable   *uint32 `json:"proxyEnable,omitempty"`
	ProxyServer   *string `json:"proxyServer,omitempty"`
	ProxyOverride *string `json:"proxyOverride,omitempty"`
	AutoConfigURL *string `json:"autoConfigURL,omitempty"`
}

// Supported reports whether automatic system proxy configuration is available.
func Supported() bool { return true }

// DefaultBackupPath returns where the previous proxy settings are stored so
// they can be restored even after an unclean exit.
func DefaultBackupPath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "socketproxy", "sysproxy-backup.json")
}

// Configure sets the system proxy to proxyAddr and returns a restore function.
func Configure(proxyAddr string) (func() error, error) {
	return ConfigureWithBackup(proxyAddr, DefaultBackupPath())
}

// ConfigureWithBackup is Configure with an explicit backup file path.
func ConfigureWithBackup(proxyAddr, backupPath string) (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		return nil, err
	}

	// Recover from a previous unclean exit before overwriting the backup.
	if data, err := os.ReadFile(backupPath); err == nil {
		var stale snapshot
		if json.Unmarshal(data, &stale) == nil {
			_ = writeSnapshot(&stale)
		}
		_ = os.Remove(backupPath)
	}

	current, err := readSnapshot()
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		return nil, err
	}

	if err := apply(proxyAddr); err != nil {
		return nil, err
	}

	restore := func() error {
		if data, err := os.ReadFile(backupPath); err == nil {
			var snap snapshot
			if json.Unmarshal(data, &snap) == nil {
				if err := writeSnapshot(&snap); err != nil {
					return err
				}
			}
		}
		notify()
		if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return restore, nil
}

func openKey() (registry.Key, error) {
	return registry.OpenKey(registry.CURRENT_USER, regPath, registry.QUERY_VALUE|registry.SET_VALUE)
}

func readSnapshot() (*snapshot, error) {
	k, err := openKey()
	if err != nil {
		return nil, err
	}
	defer k.Close()

	s := &snapshot{}
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		u := uint32(v)
		s.ProxyEnable = &u
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		s.ProxyServer = &v
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		s.ProxyOverride = &v
	}
	if v, _, err := k.GetStringValue("AutoConfigURL"); err == nil {
		s.AutoConfigURL = &v
	}
	return s, nil
}

func writeSnapshot(s *snapshot) error {
	k, err := openKey()
	if err != nil {
		return err
	}
	defer k.Close()

	if s.ProxyEnable != nil {
		if err := k.SetDWordValue("ProxyEnable", *s.ProxyEnable); err != nil {
			return err
		}
	} else {
		_ = k.DeleteValue("ProxyEnable")
	}
	if s.ProxyServer != nil {
		if err := k.SetStringValue("ProxyServer", *s.ProxyServer); err != nil {
			return err
		}
	} else {
		_ = k.DeleteValue("ProxyServer")
	}
	if s.ProxyOverride != nil {
		if err := k.SetStringValue("ProxyOverride", *s.ProxyOverride); err != nil {
			return err
		}
	} else {
		_ = k.DeleteValue("ProxyOverride")
	}
	if s.AutoConfigURL != nil {
		if err := k.SetStringValue("AutoConfigURL", *s.AutoConfigURL); err != nil {
			return err
		}
	} else {
		_ = k.DeleteValue("AutoConfigURL")
	}

	notify()
	return nil
}

func apply(proxyAddr string) error {
	k, err := openKey()
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", proxyAddr); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", "<local>"); err != nil {
		return err
	}
	_ = k.DeleteValue("AutoConfigURL")
	notify()
	return nil
}

func notify() {
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
}
