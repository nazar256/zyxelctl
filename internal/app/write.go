package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

const (
	SupportedModel    = "EX5601-T1"
	SupportedFirmware = "V5.70(ACEA.0)T56C_b29"
)

type RouterWriter interface {
	RouterAPI
	Put(context.Context, string, any) error
	Download(context.Context, string) ([]byte, error)
}

type BackupStore interface {
	LocalStore
	CreateBackupDir(time.Time) (string, error)
	WriteBackupFile(string, string, []byte) error
}

type BackupResult struct {
	Directory string   `json:"directory"`
	Files     []string `json:"files"`
}

type ConfigureResult struct {
	Changed           bool   `json:"changed"`
	BackupDirectory   string `json:"backup_directory"`
	RollbackAttempted bool   `json:"rollback_attempted"`
	RollbackVerified  bool   `json:"rollback_verified"`
}

type IsolationProbeResult struct {
	BackupDirectory  string `json:"backup_directory"`
	FlagsRetained    bool   `json:"flags_retained"`
	TargetProbed     bool   `json:"target_probed"`
	TargetReachable  bool   `json:"target_reachable"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	ProbeError       string `json:"probe_error,omitempty"`
	RollbackVerified bool   `json:"rollback_verified"`
}

type terminalWriteError struct {
	message string
}

func (e terminalWriteError) Error() string { return e.message }

func (a *App) ConfigBackup(ctx context.Context, outputDirectory string) (BackupResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return BackupResult{}, err
	}
	var result BackupResult
	err = writer.Authenticate(ctx, func() error {
		dir, err := a.backupDirectory(store, outputDirectory)
		if err != nil {
			return err
		}
		data, err := writer.Download(ctx, "/cgi-bin/Backup_Restore?action=Backup")
		if err != nil {
			return fmt.Errorf("download router configuration backup: %w", err)
		}
		if len(data) == 0 {
			return errors.New("router configuration backup was empty")
		}
		if err := store.WriteBackupFile(dir, "router.config", data); err != nil {
			return fmt.Errorf("write router configuration backup: %w", err)
		}
		result = BackupResult{Directory: dir, Files: []string{"router.config"}}
		return nil
	})
	return result, err
}

func (a *App) WiFiSnapshot(ctx context.Context, outputDirectory string) (BackupResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return BackupResult{}, err
	}
	var result BackupResult
	err = writer.Authenticate(ctx, func() error {
		_, profiles, _, err := readRouterState(ctx, writer)
		if err != nil {
			return err
		}
		targets, err := targetProfiles(profiles)
		if err != nil {
			return err
		}
		dir, err := a.backupDirectory(store, outputDirectory)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(targets, "", "  ")
		if err != nil {
			return errors.New("encode WLAN snapshot")
		}
		data = append(data, '\n')
		if err := store.WriteBackupFile(dir, "wlan-profiles-3-7.json", data); err != nil {
			return fmt.Errorf("write WLAN snapshot: %w", err)
		}
		result = BackupResult{Directory: dir, Files: []string{"wlan-profiles-3-7.json"}}
		return nil
	})
	return result, err
}

func (a *App) ConfigureIoT(ctx context.Context, ssid string, yes bool) (ConfigureResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	if ssid == "" {
		if !a.output.Interactive || a.output.Text == nil {
			return ConfigureResult{}, errors.New("network name entry requires an interactive terminal")
		}
		ssid, err = a.output.Text("Network name: ", "")
		if err != nil {
			return ConfigureResult{}, fmt.Errorf("read network name: %w", err)
		}
	}
	if err := wifi.ValidateSSID(ssid); err != nil {
		return ConfigureResult{}, err
	}
	passphrase, err := a.readConfirmedPassphrase()
	if err != nil {
		return ConfigureResult{}, err
	}
	var result ConfigureResult
	var before, targets []wifi.Profile
	var payload []map[string]any
	var dhcpBefore bool
	err = writer.Authenticate(ctx, func() error {
		identity, profiles, dhcp, err := readRouterState(ctx, writer)
		if err != nil {
			return err
		}
		if err := requireSupportedIdentity(identity); err != nil {
			return err
		}
		selected, err := targetProfiles(profiles)
		if err != nil {
			return fmt.Errorf("IoT WLAN preflight failed: %w", err)
		}
		update, err := wifi.BuildUpdatePayload(selected, ssid, passphrase)
		if err != nil {
			return fmt.Errorf("IoT WLAN preflight failed: %w", err)
		}
		backupDirectory, err := a.createChangeBackup(ctx, writer, store, identity, selected)
		if err != nil {
			return err
		}
		result.BackupDirectory = backupDirectory
		before, targets, payload, dhcpBefore = profiles, selected, update, dhcp
		return nil
	})
	if err != nil {
		return result, err
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return result, errors.New("configuration change requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Apply IoT WLAN change after backup in %s?", result.BackupDirectory))
		if err != nil {
			return result, fmt.Errorf("confirm IoT WLAN change: %w", err)
		}
		if !confirmed {
			return result, errors.New("IoT WLAN change was not confirmed")
		}
	}
	changeErr := a.applyAndVerifyChange(ctx, writer, payload, before, ssid, passphrase, dhcpBefore)
	if changeErr != nil {
		result.RollbackAttempted = true
		rollbackErr := a.rollbackAuthenticated(ctx, writer, targets, before, dhcpBefore)
		if rollbackErr != nil {
			return result, terminalWriteError{message: fmt.Sprintf("%v; rollback failed: %v", changeErr, rollbackErr)}
		}
		result.RollbackVerified = true
		return result, terminalWriteError{message: fmt.Sprintf("%v; rollback verified", changeErr)}
	}
	result.Changed = true
	return result, nil
}

func (a *App) EnableIoTPeerAccess(ctx context.Context, yes bool) (ConfigureResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	var result ConfigureResult
	var before, targets []wifi.Profile
	var payload []map[string]any
	var dhcpBefore bool
	err = writer.Authenticate(ctx, func() error {
		identity, profiles, dhcp, err := readRouterState(ctx, writer)
		if err != nil {
			return err
		}
		if err := requireSupportedIdentity(identity); err != nil {
			return err
		}
		selected, err := targetProfiles(profiles)
		if err != nil {
			return fmt.Errorf("IoT WLAN preflight failed: %w", err)
		}
		update, err := wifi.BuildPeerAccessPayload(selected)
		if err != nil {
			return fmt.Errorf("IoT peer-access preflight failed: %w", err)
		}
		backupDirectory, err := a.createChangeBackup(ctx, writer, store, identity, selected)
		if err != nil {
			return err
		}
		result.BackupDirectory = backupDirectory
		before, targets, payload, dhcpBefore = profiles, selected, update, dhcp
		return nil
	})
	if err != nil {
		return result, err
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return result, errors.New("peer-access change requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Try IoT peer access after backup in %s? Manual connectivity verification is still required", result.BackupDirectory))
		if err != nil {
			return result, fmt.Errorf("confirm IoT peer-access change: %w", err)
		}
		if !confirmed {
			return result, errors.New("IoT peer-access change was not confirmed")
		}
	}
	changeErr := a.applyAndVerifyPeerAccess(ctx, writer, payload, before, dhcpBefore)
	if changeErr != nil {
		result.RollbackAttempted = true
		rollbackErr := a.rollbackAuthenticated(ctx, writer, targets, before, dhcpBefore)
		if rollbackErr != nil {
			return result, terminalWriteError{message: fmt.Sprintf("%v; rollback failed: %v", changeErr, rollbackErr)}
		}
		result.RollbackVerified = true
		return result, terminalWriteError{message: fmt.Sprintf("%v; rollback verified", changeErr)}
	}
	result.Changed = true
	return result, nil
}

// ProbeIoTIsolation tests the narrow flag-only payload and always restores the
// original WLAN pair before returning, whether the HTTP target answers or not.
func (a *App) ProbeIoTIsolation(ctx context.Context, target string, yes bool) (IsolationProbeResult, error) {
	if err := validateProbeTarget(target); err != nil {
		return IsolationProbeResult{}, err
	}
	writer, store, err := a.writeDependencies()
	if err != nil {
		return IsolationProbeResult{}, err
	}
	var result IsolationProbeResult
	var before, targets []wifi.Profile
	var payload []map[string]any
	var dhcpBefore bool
	err = writer.Authenticate(ctx, func() error {
		identity, profiles, dhcp, err := readRouterState(ctx, writer)
		if err != nil {
			return err
		}
		if err := requireSupportedIdentity(identity); err != nil {
			return err
		}
		selected, err := targetProfiles(profiles)
		if err != nil {
			return fmt.Errorf("IoT WLAN preflight failed: %w", err)
		}
		update, err := wifi.BuildIsolationProbePayload(selected)
		if err != nil {
			return fmt.Errorf("isolation probe preflight failed: %w", err)
		}
		backupDirectory, err := a.createChangeBackup(ctx, writer, store, identity, selected)
		if err != nil {
			return err
		}
		result.BackupDirectory = backupDirectory
		before, targets, payload, dhcpBefore = profiles, selected, update, dhcp
		return nil
	})
	if err != nil {
		return result, err
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return result, errors.New("isolation probe requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Briefly probe IoT isolation after backup in %s and then restore it?", result.BackupDirectory))
		if err != nil {
			return result, fmt.Errorf("confirm isolation probe: %w", err)
		}
		if !confirmed {
			return result, errors.New("isolation probe was not confirmed")
		}
	}
	retained, writeAttempted, changeErr := a.applyAndClassifyIsolation(ctx, writer, payload, before, targets, dhcpBefore)
	if !writeAttempted {
		return result, changeErr
	}
	if changeErr == nil && !retained {
		result.RollbackVerified = true // readback already matches the original state
		return result, nil
	}
	if changeErr == nil {
		result.FlagsRetained = true
		result.TargetProbed = true
		status, probeErr := a.output.Probe(ctx, target)
		if probeErr != nil {
			result.ProbeError = probeErr.Error()
		} else {
			result.TargetReachable = true
			result.HTTPStatus = status
		}
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	rollbackErr := a.rollbackAuthenticated(rollbackCtx, writer, targets, before, dhcpBefore)
	if rollbackErr != nil {
		return result, terminalWriteError{message: fmt.Sprintf("isolation probe restore failed: %v; manual recovery from %s may be required", rollbackErr, result.BackupDirectory)}
	}
	result.RollbackVerified = true
	if changeErr != nil {
		return result, terminalWriteError{message: fmt.Sprintf("isolation probe did not retain the requested flags (%v); rollback verified", changeErr)}
	}
	return result, nil
}

func (a *App) applyAndClassifyIsolation(ctx context.Context, writer RouterWriter, payload []map[string]any, before, targets []wifi.Profile, dhcpBefore bool) (bool, bool, error) {
	if err := a.authenticateOnly(ctx, writer); err != nil {
		return false, false, fmt.Errorf("authenticate isolation probe: %w", err)
	}
	if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", payload); err != nil {
		return false, true, fmt.Errorf("update isolation flags: %w", err)
	}
	if err := a.checkWLANAuthenticated(ctx, writer); err != nil {
		return false, true, fmt.Errorf("check updated WLAN: %w", err)
	}
	a.output.Sleep(15 * time.Second)
	var retained bool
	err := writer.Authenticate(ctx, func() error {
		identity, current, dhcpCurrent, err := readRouterState(ctx, writer)
		if err != nil {
			return fmt.Errorf("read isolation probe state: %w", err)
		}
		if err := requireSupportedIdentity(identity); err != nil {
			return err
		}
		if err := wifi.VerifyPeerAccessChange(before, current, dhcpBefore, dhcpCurrent); err == nil {
			retained = true
			return nil
		}
		if err := wifi.VerifyChange(before, current, targets[0].SSID, targets[0].PskDisplay, dhcpBefore, dhcpCurrent); err == nil {
			return nil
		}
		return errors.New("isolation probe caused an unexpected WLAN or DHCP state")
	})
	return retained, true, err
}

func (a *App) rollbackAuthenticated(ctx context.Context, writer RouterWriter, targets, before []wifi.Profile, dhcpBefore bool) error {
	payload, err := wifi.BuildRestorePayload(targets)
	if err != nil {
		return err
	}
	if err := a.authenticateOnly(ctx, writer); err != nil {
		return fmt.Errorf("authenticate rollback: %w", err)
	}
	putErr := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", payload)
	checkErr := a.checkWLANAuthenticated(ctx, writer)
	if putErr == nil && checkErr != nil {
		return checkErr
	}
	a.output.Sleep(15 * time.Second)
	verifyErr := a.verifyRollbackAuthenticated(ctx, writer, targets, before, dhcpBefore)
	if verifyErr != nil && putErr != nil {
		return fmt.Errorf("rollback PUT outcome uncertain (%v); %w", putErr, verifyErr)
	}
	return verifyErr
}

func (a *App) applyAndVerifyChange(ctx context.Context, writer RouterWriter, payload []map[string]any, before []wifi.Profile, ssid, passphrase string, dhcpBefore bool) error {
	if err := a.authenticateOnly(ctx, writer); err != nil {
		return fmt.Errorf("authenticate IoT WLAN update: %w", err)
	}
	if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", payload); err != nil {
		return fmt.Errorf("update IoT WLAN: %w", err)
	}
	if err := a.checkWLANAuthenticated(ctx, writer); err != nil {
		return fmt.Errorf("check updated WLAN: %w", err)
	}
	a.output.Sleep(15 * time.Second)
	return a.verifyChangeAuthenticated(ctx, writer, before, ssid, passphrase, dhcpBefore)
}

func (a *App) applyAndVerifyPeerAccess(ctx context.Context, writer RouterWriter, payload []map[string]any, before []wifi.Profile, dhcpBefore bool) error {
	if err := a.authenticateOnly(ctx, writer); err != nil {
		return fmt.Errorf("authenticate IoT peer-access update: %w", err)
	}
	if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", payload); err != nil {
		return fmt.Errorf("update IoT peer access: %w", err)
	}
	if err := a.checkWLANAuthenticated(ctx, writer); err != nil {
		return fmt.Errorf("check updated WLAN: %w", err)
	}
	a.output.Sleep(15 * time.Second)
	return a.verifyPeerAccessAuthenticated(ctx, writer, before, dhcpBefore)
}

func (a *App) authenticateOnly(ctx context.Context, writer RouterWriter) error {
	return writer.Authenticate(ctx, func() error { return nil })
}

func (a *App) checkWLANAuthenticated(ctx context.Context, writer RouterWriter) error {
	return writer.Authenticate(ctx, func() error {
		var check any
		return writer.Get(ctx, "/cgi-bin/Wireless?action=WlCheck", &check)
	})
}

func (a *App) verifyChangeAuthenticated(ctx context.Context, writer RouterWriter, before []wifi.Profile, ssid, passphrase string, dhcpBefore bool) error {
	return writer.Authenticate(ctx, func() error {
		afterIdentity, after, dhcpAfter, err := readRouterState(ctx, writer)
		if err != nil {
			return fmt.Errorf("verify updated router state: %w", err)
		}
		if err := requireSupportedIdentity(afterIdentity); err != nil {
			return err
		}
		if err := wifi.VerifyChange(before, after, ssid, passphrase, dhcpBefore, dhcpAfter); err != nil {
			return fmt.Errorf("verify updated IoT WLAN: %w", err)
		}
		return nil
	})
}

func (a *App) verifyPeerAccessAuthenticated(ctx context.Context, writer RouterWriter, before []wifi.Profile, dhcpBefore bool) error {
	return writer.Authenticate(ctx, func() error {
		afterIdentity, after, dhcpAfter, err := readRouterState(ctx, writer)
		if err != nil {
			return fmt.Errorf("verify updated router state: %w", err)
		}
		if err := requireSupportedIdentity(afterIdentity); err != nil {
			return err
		}
		if err := wifi.VerifyPeerAccessChange(before, after, dhcpBefore, dhcpAfter); err != nil {
			return fmt.Errorf("verify updated IoT peer access: %w", err)
		}
		return nil
	})
}

func (a *App) verifyRollbackAuthenticated(ctx context.Context, writer RouterWriter, targets, before []wifi.Profile, dhcpBefore bool) error {
	return writer.Authenticate(ctx, func() error {
		identity, current, dhcpCurrent, err := readRouterState(ctx, writer)
		if err != nil {
			return fmt.Errorf("rollback verification failed: %w", err)
		}
		if err := requireSupportedIdentity(identity); err != nil {
			return fmt.Errorf("rollback verification failed: %w", err)
		}
		if err := wifi.VerifyChange(before, current, targets[0].SSID, targets[0].PskDisplay, dhcpBefore, dhcpCurrent); err != nil {
			return fmt.Errorf("rollback verification failed: %w", err)
		}
		return nil
	})
}

func (a *App) WiFiRestore(ctx context.Context, snapshotPath string, yes bool) (ConfigureResult, error) {
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		return ConfigureResult{}, fmt.Errorf("read WLAN snapshot: %w", err)
	}
	var snapshot []wifi.Profile
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return ConfigureResult{}, errors.New("WLAN snapshot is not valid JSON")
	}
	payload, err := wifi.BuildRestorePayload(snapshot)
	if err != nil {
		return ConfigureResult{}, err
	}
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	var result ConfigureResult
	var before, currentTargets []wifi.Profile
	var dhcpBefore bool
	err = writer.Authenticate(ctx, func() error {
		identity, profiles, dhcp, err := readRouterState(ctx, writer)
		if err != nil {
			return err
		}
		if err := requireSupportedIdentity(identity); err != nil {
			return err
		}
		selected, err := targetProfiles(profiles)
		if err != nil {
			return fmt.Errorf("current IoT WLAN preflight failed: %w", err)
		}
		backupDirectory, err := a.createChangeBackup(ctx, writer, store, identity, selected)
		if err != nil {
			return err
		}
		result.BackupDirectory = backupDirectory
		before, currentTargets, dhcpBefore = profiles, selected, dhcp
		return nil
	})
	if err != nil {
		return result, err
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return result, errors.New("WLAN restore requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Restore WLAN profiles from %s after backup in %s?", snapshotPath, result.BackupDirectory))
		if err != nil {
			return result, fmt.Errorf("confirm WLAN restore: %w", err)
		}
		if !confirmed {
			return result, errors.New("WLAN restore was not confirmed")
		}
	}
	restoreErr := a.applyAndVerifyChange(ctx, writer, payload, before, snapshot[0].SSID, snapshot[0].PskDisplay, dhcpBefore)
	if restoreErr != nil {
		result.RollbackAttempted = true
		rollbackErr := a.rollbackAuthenticated(ctx, writer, currentTargets, before, dhcpBefore)
		if rollbackErr != nil {
			return result, terminalWriteError{message: fmt.Sprintf("%v; rollback failed: %v", restoreErr, rollbackErr)}
		}
		result.RollbackVerified = true
		return result, terminalWriteError{message: fmt.Sprintf("%v; rollback verified", restoreErr)}
	}
	result.Changed = true
	return result, nil
}

func (a *App) createChangeBackup(ctx context.Context, writer RouterWriter, store BackupStore, identity router.Identity, targets []wifi.Profile) (string, error) {
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return "", fmt.Errorf("create pre-change backup: %w", err)
	}
	config, err := writer.Download(ctx, "/cgi-bin/Backup_Restore?action=Backup")
	if err != nil {
		return "", fmt.Errorf("download pre-change configuration: %w", err)
	}
	if len(config) == 0 {
		return "", errors.New("pre-change configuration backup was empty")
	}
	if err := store.WriteBackupFile(dir, "router.config", config); err != nil {
		return "", fmt.Errorf("write pre-change configuration: %w", err)
	}
	snapshot, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return "", errors.New("encode pre-change WLAN snapshot")
	}
	if err := store.WriteBackupFile(dir, "wlan-profiles-3-7.json", append(snapshot, '\n')); err != nil {
		return "", fmt.Errorf("write pre-change WLAN snapshot: %w", err)
	}
	manifest, err := json.MarshalIndent(map[string]any{
		"captured_at": a.output.Now().UTC(),
		"model":       identity.Model,
		"firmware":    identity.Firmware,
		"profiles":    []int{3, 7},
		"files":       []string{"router.config", "wlan-profiles-3-7.json"},
	}, "", "  ")
	if err != nil {
		return "", errors.New("encode backup manifest")
	}
	if err := store.WriteBackupFile(dir, "manifest.json", append(manifest, '\n')); err != nil {
		return "", fmt.Errorf("write backup manifest: %w", err)
	}
	return dir, nil
}

func (a *App) readConfirmedPassphrase() (string, error) {
	if !a.output.Interactive || a.output.Password == nil {
		return "", errors.New("Wi-Fi password entry requires an interactive terminal")
	}
	first, err := a.output.Password("Wi-Fi password: ")
	if err != nil {
		return "", fmt.Errorf("read Wi-Fi password: %w", err)
	}
	second, err := a.output.Password("Confirm Wi-Fi password: ")
	if err != nil {
		return "", fmt.Errorf("confirm Wi-Fi password: %w", err)
	}
	if first != second {
		return "", errors.New("Wi-Fi passwords do not match")
	}
	if err := wifi.ValidatePassphrase(first); err != nil {
		return "", err
	}
	return first, nil
}

func (a *App) writeDependencies() (RouterWriter, BackupStore, error) {
	writer, ok := a.router.(RouterWriter)
	if !ok {
		return nil, nil, errors.New("router write operations are unavailable")
	}
	store, ok := a.store.(BackupStore)
	if !ok {
		return nil, nil, errors.New("backup storage is unavailable")
	}
	return writer, store, nil
}

func (a *App) backupDirectory(store BackupStore, requested string) (string, error) {
	if requested != "" {
		return requested, nil
	}
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	return dir, nil
}

func readRouterState(ctx context.Context, writer RouterWriter) (router.Identity, []wifi.Profile, bool, error) {
	identity, err := writer.ReadIdentity(ctx)
	if err != nil {
		return router.Identity{}, nil, false, err
	}
	var wlan wlanResponse
	if err := writer.Get(ctx, "/cgi-bin/DAL?oid=wlan", &wlan); err != nil {
		return router.Identity{}, nil, false, err
	}
	var lan lanResponse
	if err := writer.Get(ctx, "/cgi-bin/DAL?oid=lan", &lan); err != nil {
		return router.Identity{}, nil, false, err
	}
	if len(lan.Object) == 0 {
		return router.Identity{}, nil, false, errors.New("router returned no LAN configuration")
	}
	return identity, wlan.Object, lan.Object[0].EnableDHCP, nil
}

func targetProfiles(profiles []wifi.Profile) ([]wifi.Profile, error) {
	targets := make([]wifi.Profile, 0, 2)
	for _, profile := range profiles {
		if profile.Index == 3 || profile.Index == 7 {
			targets = append(targets, profile)
		}
	}
	if err := wifi.ValidatePair(targets); err != nil {
		return nil, err
	}
	return targets, nil
}

func requireSupportedIdentity(identity router.Identity) error {
	if identity.Model != SupportedModel || identity.Firmware != SupportedFirmware {
		return fmt.Errorf("unsupported router identity %q firmware %q; refusing to change configuration", identity.Model, identity.Firmware)
	}
	return nil
}
