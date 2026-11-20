package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Paths struct {
	ConfigFile string
	StateFile  string
	BackupRoot string
}

type Config struct {
	RouterURL       string `json:"router_url"`
	Username        string `json:"username"`
	CertFingerprint string `json:"certificate_sha256"`
}

type State struct {
	Peer            Config            `json:"peer,omitzero"`
	AESKey          string            `json:"aes_key"`
	CSRFToken       string            `json:"csrf_token"`
	Cookies         map[string]string `json:"cookies,omitempty"`
	Model           string            `json:"model,omitempty"`
	Firmware        string            `json:"firmware,omitempty"`
	LoggedInAt      time.Time         `json:"logged_in_at"`
	LastValidatedAt time.Time         `json:"last_validated_at,omitempty"`
}

type Store struct {
	Paths  Paths
	rename func(string, string) error
}

func NewPaths(env map[string]string, home string) Paths {
	configRoot := env["XDG_CONFIG_HOME"]
	if configRoot == "" {
		configRoot = filepath.Join(home, ".config")
	}
	stateRoot := env["XDG_STATE_HOME"]
	if stateRoot == "" {
		stateRoot = filepath.Join(home, ".local", "state")
	}
	return Paths{
		ConfigFile: filepath.Join(configRoot, "zyxelctl", "config.json"),
		StateFile:  filepath.Join(stateRoot, "zyxelctl", "session.json"),
		BackupRoot: filepath.Join(stateRoot, "zyxelctl", "backups"),
	}
}

func NewStore(paths Paths) *Store {
	return &Store{Paths: paths, rename: os.Rename}
}

// ForDevice keeps the existing router paths intact and gives the extender its
// own certificate configuration, authenticated session, and backup directory.
func (p Paths) ForDevice(device string) (Paths, error) {
	switch device {
	case "router":
		return p, nil
	case "extender":
		return Paths{
			ConfigFile: filepath.Join(filepath.Dir(p.ConfigFile), "extender", "config.json"),
			StateFile:  filepath.Join(filepath.Dir(p.StateFile), "extender", "session.json"),
			BackupRoot: filepath.Join(filepath.Dir(p.StateFile), "extender", "backups"),
		}, nil
	default:
		return Paths{}, errors.New("device must be router or extender")
	}
}

func (s *Store) LoadConfig() (Config, error) {
	var value Config
	err := loadJSON(s.Paths.ConfigFile, &value)
	return value, err
}

func (s *Store) SaveConfig(value Config) error {
	return s.saveJSON(s.Paths.ConfigFile, value)
}

func (s *Store) LoadState() (State, error) {
	var value State
	err := loadJSON(s.Paths.StateFile, &value)
	return value, err
}

func (s *Store) SaveState(value State) error {
	return s.saveJSON(s.Paths.StateFile, value)
}

func (s *Store) Logout() error {
	if s.Paths.StateFile == "" {
		return nil
	}
	info, err := os.Lstat(s.Paths.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect session state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refusing to remove non-regular session state")
	}
	if err := os.Remove(s.Paths.StateFile); err != nil {
		return fmt.Errorf("remove session state: %w", err)
	}
	return syncDir(filepath.Dir(s.Paths.StateFile))
}

func (s *Store) CreateBackupDir(when time.Time) (string, error) {
	if err := ensureSecureDir(s.Paths.BackupRoot); err != nil {
		return "", fmt.Errorf("prepare backup root: %w", err)
	}
	utc := when.UTC()
	name := utc.Format("2006-01-02T15-04-05") + fmt.Sprintf("-%03dZ", utc.Nanosecond()/int(time.Millisecond))
	dir := filepath.Join(s.Paths.BackupRoot, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("secure backup directory: %w", err)
	}
	return dir, nil
}

func (s *Store) WriteBackupFile(dir, name string, data []byte) error {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("backup name must be a plain file name")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return errors.New("invalid backup directory")
	}
	if err := ensureSecureDir(absDir); err != nil {
		return fmt.Errorf("validate backup directory: %w", err)
	}
	return s.atomicWrite(filepath.Join(absDir, name), data)
}

func (s *Store) saveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')
	return s.atomicWrite(path, data)
}

func (s *Store) atomicWrite(path string, data []byte) (returnErr error) {
	if path == "" {
		return errors.New("storage path is empty")
	}
	dir := filepath.Dir(path)
	if err := ensureSecureDir(dir); err != nil {
		return fmt.Errorf("prepare private directory: %w", err)
	}
	if err := rejectUnsafeFile(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		removeErr := os.Remove(tmpName)
		if returnErr == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			returnErr = fmt.Errorf("clean temporary state: %w", removeErr)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary state: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}
	if err := s.rename(tmpName, path); err != nil {
		return fmt.Errorf("replace state atomically: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure state: %w", err)
	}
	return syncDir(dir)
}

func loadJSON(path string, target any) error {
	if err := rejectUnsafeFile(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("stored state permissions are not owner-only")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read stored state: %w", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.New("stored state is not valid JSON")
	}
	return nil
}

func rejectUnsafeFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect storage file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refusing to use non-regular storage file")
	}
	return nil
}

func ensureSecureDir(path string) error {
	if path == "" {
		return errors.New("directory path is empty")
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private directory is not a real directory")
	}
	return os.Chmod(path, 0o700)
}

func rejectSymlinkComponents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	volume := filepath.VolumeName(abs)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	trimmed := strings.TrimPrefix(abs, current)
	for _, part := range strings.Split(trimmed, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink path component %q", current)
		}
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
