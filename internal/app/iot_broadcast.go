package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

// SetIoTBroadcast enables or disables only the IoT guest BSSes on the
// connected device. On the gateway each differing profile gets one narrow
// wlEnable write (disable) or the guest editor restore payload (enable, so
// profile 3's subnet object is rebuilt when the profile retains one).
// Other networks, radios, credentials, LAN and mesh settings are untouched;
// a pair member already in the requested state is left alone.
func (a *App) SetIoTBroadcast(ctx context.Context, enabled, yes bool) (ConfigureResult, error) {
	result := ConfigureResult{}
	writer, store, err := a.writeDependencies()
	if err != nil {
		return result, err
	}
	var identity router.Identity
	if err := writer.Authenticate(ctx, func() error {
		var err error
		identity, err = writer.ReadIdentity(ctx)
		return err
	}); err != nil {
		return result, err
	}
	if identity.Model != SupportedModel {
		return a.SetExtenderIoTBroadcast(ctx, enabled, yes)
	}
	read := func(ctx context.Context, target *bandSyncState) error {
		return writer.Authenticate(ctx, func() error {
			var err error
			*target, err = readBandSyncState(ctx, writer)
			return err
		})
	}
	var before bandSyncState
	if err := read(ctx, &before); err != nil {
		return result, err
	}
	pair, ssid, err := iotGuestPair(before)
	if err != nil {
		return result, err
	}
	var targets []int
	for _, index := range []int{3, 7} {
		if pair[index].WLEnable != enabled {
			targets = append(targets, index)
		}
	}
	if len(targets) == 0 {
		return result, nil
	}
	if enabled && slices.Contains(targets, 3) {
		if err := wifi.ValidatePassphrase(pair[3].PskDisplay); err != nil {
			return result, errors.New("existing IoT passphrase is unavailable")
		}
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return result, errors.New("IoT broadcast change requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Set %q broadcasting on the gateway to %t? Its clients must move to another network.", ssid, enabled))
		if err != nil {
			return result, err
		}
		if !confirmed {
			return result, errors.New("IoT broadcast change was not confirmed")
		}
	}
	dir, err := a.createChangeBackup(ctx, writer, store, identity, []wifi.Profile{pair[3], pair[7]})
	if err != nil {
		return result, err
	}
	result.BackupDirectory = dir
	var current bandSyncState
	if err := read(ctx, &current); err != nil {
		return result, err
	}
	if err := verifyIoTRadio(before, current, nil); err != nil {
		return result, fmt.Errorf("router changed during IoT broadcast preflight: %w", err)
	}
	attempted := []int{}
	putPayload := func(ctx context.Context, payload map[string]any) error {
		index, _ := payload["Index"].(int)
		if err := a.authenticateOnly(ctx, writer); err != nil {
			return err
		}
		if !slices.Contains(attempted, index) {
			attempted = append(attempted, index)
		}
		if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", payload); err != nil {
			return fmt.Errorf("update IoT profile %d: %w", index, err)
		}
		return a.checkWLANAuthenticated(ctx, writer)
	}
	applied := map[int]bool{}
	changeErr := error(nil)
	for _, index := range targets {
		var payload map[string]any
		if enabled {
			desired := pair[index]
			desired.WLEnable = true
			var currentProfile *wifi.Profile
			for i := range current.Profiles {
				if current.Profiles[i].Index == index {
					currentProfile = &current.Profiles[i]
				}
			}
			if currentProfile == nil {
				changeErr = fmt.Errorf("IoT profile %d missing during broadcast change", index)
				break
			}
			payload, err = iotRadioRestorePayload(desired, *currentProfile)
			if err != nil {
				changeErr = err
				break
			}
		} else {
			payload = map[string]any{"Index": index, "wlEnable": false}
		}
		if err := putPayload(ctx, payload); err != nil {
			changeErr = err
			break
		}
		applied[index] = enabled
		a.output.Sleep(3 * time.Second)
		if err := read(ctx, &current); err != nil {
			changeErr = err
			break
		}
		if err := verifyIoTRadio(before, current, applied); err != nil {
			changeErr = fmt.Errorf("set IoT profile %d broadcasting to %t left unexpected state: %w", index, enabled, err)
			break
		}
	}
	if changeErr == nil {
		changeErr = read(ctx, &current)
	}
	if changeErr == nil {
		changeErr = verifyIoTRadio(before, current, applied)
	}
	if changeErr == nil {
		result.Changed = true
		return result, nil
	}
	if len(attempted) == 0 {
		return result, changeErr
	}
	result.RollbackAttempted = true
	if rollbackErr := a.restoreIoTRadioProfiles(read, writer, before, current, attempted); rollbackErr != nil {
		return result, terminalWriteError{message: fmt.Sprintf("%v; rollback failed: %v; backup %s", changeErr, rollbackErr, dir)}
	}
	result.RollbackVerified = true
	return result, terminalWriteError{message: fmt.Sprintf("%v; rollback verified; backup %s", changeErr, dir)}
}
