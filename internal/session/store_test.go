package session

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	paths := NewPaths(map[string]string{
		"XDG_CONFIG_HOME": filepath.Join(root, "config"),
		"XDG_STATE_HOME":  filepath.Join(root, "state"),
	}, filepath.Join(root, "home"))
	return NewStore(paths)
}

func TestNewPathsUsesXDGAndHomeFallbacks(t *testing.T) {
	got := NewPaths(map[string]string{
		"XDG_CONFIG_HOME": "/xdg/config",
		"XDG_STATE_HOME":  "/xdg/state",
	}, "/home/tester")
	want := Paths{
		ConfigFile: filepath.FromSlash("/xdg/config/zyxelctl/config.json"),
		StateFile:  filepath.FromSlash("/xdg/state/zyxelctl/session.json"),
		BackupRoot: filepath.FromSlash("/xdg/state/zyxelctl/backups"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NewPaths() = %#v, want %#v", got, want)
	}

	fallback := NewPaths(nil, "/home/tester")
	if fallback.ConfigFile != filepath.FromSlash("/home/tester/.config/zyxelctl/config.json") {
		t.Fatalf("fallback config = %q", fallback.ConfigFile)
	}
	if fallback.StateFile != filepath.FromSlash("/home/tester/.local/state/zyxelctl/session.json") {
		t.Fatalf("fallback state = %q", fallback.StateFile)
	}
}

func TestDevicePathsPreserveLegacyRouterAndSeparateExtender(t *testing.T) {
	base := NewPaths(nil, "/home/tester")
	routerPaths, err := base.ForDevice("router")
	if err != nil || !reflect.DeepEqual(base, routerPaths) {
		t.Fatalf("router paths changed: %#v, %v", routerPaths, err)
	}
	extenderPaths, err := base.ForDevice("extender")
	want := Paths{
		ConfigFile: "/home/tester/.config/zyxelctl/extender/config.json",
		StateFile:  "/home/tester/.local/state/zyxelctl/extender/session.json",
		BackupRoot: "/home/tester/.local/state/zyxelctl/extender/backups",
	}
	if err != nil || !reflect.DeepEqual(want, extenderPaths) {
		t.Fatalf("extender paths = %#v, %v", extenderPaths, err)
	}
	if _, err := base.ForDevice("../router"); err == nil {
		t.Fatal("invalid device path accepted")
	}
}

func TestStoreRoundTripsOwnerOnlyConfigAndState(t *testing.T) {
	store := testStore(t)
	config := Config{RouterURL: "https://192.168.1.1", Username: "admin", CertFingerprint: "AA:BB"}
	state := State{
		AESKey: "base64-aes-key", CSRFToken: "csrf-token",
		Cookies: map[string]string{"Session": "cookie-value"},
		Model:   "EX5601-T1", Firmware: "V5.70(ACEA.0)T56C_b29",
		LoggedInAt: time.Date(2024, 1, 2, 8, 0, 0, 0, time.UTC),
	}
	if err := store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveState(state); err != nil {
		t.Fatal(err)
	}
	gotConfig, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	gotState, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotConfig, config) {
		t.Fatalf("config = %#v, want %#v", gotConfig, config)
	}
	if !reflect.DeepEqual(gotState, state) {
		t.Fatalf("state = %#v, want %#v", gotState, state)
	}

	for _, path := range []string{store.Paths.ConfigFile, store.Paths.StateFile} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 600", path, got)
		}
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := parent.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %o, want 700", filepath.Dir(path), got)
		}
	}
}

func TestStoredStateContainsNoRouterOrWiFiPassword(t *testing.T) {
	store := testStore(t)
	routerPassword := "router-password-fixture"
	wifiPassword := "wifi-password-fixture"
	state := State{AESKey: "aes", CSRFToken: "csrf", Cookies: map[string]string{"Session": "cookie"}}
	if err := store.SaveState(state); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.Paths.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{routerPassword, wifiPassword} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("state contains forbidden password %q", forbidden)
		}
	}
}

func TestAtomicSaveFailurePreservesOldStateAndCleansTemporaryFile(t *testing.T) {
	store := testStore(t)
	oldState := State{AESKey: "old-key", CSRFToken: "old-token"}
	if err := store.SaveState(oldState); err != nil {
		t.Fatal(err)
	}
	store.rename = func(_, _ string) error { return errors.New("injected rename failure") }
	if err := store.SaveState(State{AESKey: "new-key", CSRFToken: "new-token"}); err == nil {
		t.Fatal("SaveState() error = nil")
	}
	got, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, oldState) {
		t.Fatalf("state after failed save = %#v, want %#v", got, oldState)
	}
	entries, err := os.ReadDir(filepath.Dir(store.Paths.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestStoreRejectsSymlinkFileAndDirectory(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		store := testStore(t)
		if err := os.MkdirAll(filepath.Dir(store.Paths.ConfigFile), 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, store.Paths.ConfigFile); err != nil {
			t.Fatal(err)
		}
		if err := store.SaveConfig(Config{RouterURL: "https://router"}); err == nil {
			t.Fatal("SaveConfig() accepted symlink file")
		}
	})

	t.Run("directory", func(t *testing.T) {
		root := t.TempDir()
		realDir := filepath.Join(root, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(root, "config-link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		paths := Paths{ConfigFile: filepath.Join(linkDir, "config.json")}
		if err := NewStore(paths).SaveConfig(Config{RouterURL: "https://router"}); err == nil {
			t.Fatal("SaveConfig() accepted symlink directory")
		}
	})
}

func TestLogoutRemovesOnlySession(t *testing.T) {
	store := testStore(t)
	if err := store.SaveConfig(Config{RouterURL: "https://router"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveState(State{AESKey: "key"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Logout(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Paths.StateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(store.Paths.ConfigFile); err != nil {
		t.Fatalf("config removed by Logout: %v", err)
	}
	if err := store.Logout(); err != nil {
		t.Fatalf("second Logout() error = %v", err)
	}
}

func TestBackupDirectoryAndFilesAreOwnerOnly(t *testing.T) {
	store := testStore(t)
	when := time.Date(2024, 1, 2, 8, 9, 10, 123000000, time.UTC)
	dir, err := store.CreateBackupDir(when)
	if err != nil {
		t.Fatal(err)
	}
	wantSuffix := filepath.Join("backups", "2024-01-02T08-09-10-123Z")
	if !strings.HasSuffix(dir, wantSuffix) {
		t.Fatalf("backup dir = %q, want suffix %q", dir, wantSuffix)
	}
	if err := store.WriteBackupFile(dir, "router.config", []byte("backup")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, filepath.Join(dir, "router.config")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o700)
		if !info.IsDir() {
			want = 0o600
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}
	if err := store.WriteBackupFile(dir, "../escape", []byte("bad")); err == nil {
		t.Fatal("WriteBackupFile accepted path traversal")
	}
}

func TestWriteBackupFileSupportsExplicitDirectory(t *testing.T) {
	store := testStore(t)
	dir := filepath.Join(t.TempDir(), "operator-selected")
	if err := store.WriteBackupFile(dir, "router.config", []byte("backup")); err != nil {
		t.Fatalf("WriteBackupFile() error = %v", err)
	}
	for _, path := range []string{dir, filepath.Join(dir, "router.config")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o700)
		if !info.IsDir() {
			want = 0o600
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}
}
