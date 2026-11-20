package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

// supportedExtenders lists the extender identities admitted to guarded
// writes. Firmware b27 speaks the modern login protocol; the b13-specific
// legacy session handling in router/auth.go does not apply to it.
var supportedExtenders = []router.Identity{
	{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b13"},
	{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b27"},
}

func requireSupportedExtender(identity router.Identity) error {
	if !slices.Contains(supportedExtenders, identity) {
		return errors.New("IoT guest-mode repair requires the supported WX5600-T0 extender")
	}
	return nil
}

// SetExtenderIoTHomeGuest changes only the guest mode, using the same fields
// as the extender UI. Credentials and other WLAN settings are never resent.
func (a *App) SetExtenderIoTHomeGuest(ctx context.Context, yes bool) (ConfigureResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	var identity router.Identity
	var before []wifi.Profile
	var dhcpBefore bool
	var originalModes map[int]int
	var ssid string
	err = writer.Authenticate(ctx, func() error {
		var err error
		identity, before, dhcpBefore, err = readRouterState(ctx, writer)
		if err != nil {
			return err
		}
		if err := requireSupportedExtender(identity); err != nil {
			return err
		}
		if ssid, err = wifi.GuestPairSSID(before); err != nil {
			return err
		}
		originalModes, err = wifi.ExtenderIoTModes(before)
		return err
	})
	if err != nil {
		return ConfigureResult{}, err
	}
	if originalModes[3] == 1 && originalModes[7] == 1 {
		return ConfigureResult{}, nil
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return ConfigureResult{}, errors.New("extender guest-mode change requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Set only %q to Home Guest on the extender, retaining network isolation?", ssid))
		if err != nil {
			return ConfigureResult{}, err
		}
		if !confirmed {
			return ConfigureResult{}, errors.New("extender guest-mode change was not confirmed")
		}
	}
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return ConfigureResult{}, err
	}
	result := ConfigureResult{BackupDirectory: dir}
	// Only mode fields are needed for rollback; this backup contains no passwords.
	backup, err := json.MarshalIndent(map[string]any{"model": identity.Model, "firmware": identity.Firmware, "ssid": ssid, "modes": originalModes}, "", "  ")
	if err != nil {
		return result, errors.New("encode IoT mode backup")
	}
	if err := store.WriteBackupFile(dir, "iot-guest-mode.json", append(backup, '\n')); err != nil {
		return result, err
	}
	desiredModes := map[int]int{3: 1, 7: 1}
	updates := make(map[int]int, 2)
	for index, mode := range originalModes {
		if mode != 1 {
			updates[index] = 1
		}
	}
	attempted, changeErr := a.applyExtenderIoTModes(ctx, writer, updates)
	if changeErr == nil {
		changeErr = verifyExtenderIoTModes(ctx, writer, before, desiredModes, dhcpBefore)
	}
	if changeErr == nil {
		result.Changed = true
		return result, nil
	}
	result.RollbackAttempted = true
	rollbackModes := make(map[int]int, len(attempted))
	for _, index := range attempted {
		rollbackModes[index] = originalModes[index]
	}
	_, rollbackErr := a.applyExtenderIoTModes(ctx, writer, rollbackModes)
	if rollbackErr == nil {
		rollbackErr = verifyExtenderIoTModes(ctx, writer, before, originalModes, dhcpBefore)
	}
	if rollbackErr != nil {
		return result, terminalWriteError{message: fmt.Sprintf("%v; rollback failed: %v; original modes saved in %s", changeErr, rollbackErr, dir)}
	}
	result.RollbackVerified = true
	return result, terminalWriteError{message: fmt.Sprintf("%v; rollback verified", changeErr)}
}

func (a *App) applyExtenderIoTModes(ctx context.Context, writer RouterWriter, modes map[int]int) ([]int, error) {
	var attempted []int
	if err := a.authenticateOnly(ctx, writer); err != nil {
		return attempted, err
	}
	// Authenticate can retry its callback. Keep each mutation outside it so
	// an uncertain response never causes a previously attempted PUT to replay.
	for _, index := range []int{3, 7} {
		mode, change := modes[index]
		if !change {
			continue
		}
		attempted = append(attempted, index)
		if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", map[string]any{"Index": index, "wlEnableGuest": true, "wlGwMode": mode}); err != nil {
			return attempted, fmt.Errorf("update extender IoT profile %d: %w", index, err)
		}
		if err := a.checkWLANAuthenticated(ctx, writer); err != nil {
			return attempted, fmt.Errorf("apply extender IoT profile %d: %w", index, err)
		}
	}
	return attempted, nil
}

func verifyExtenderIoTModes(ctx context.Context, writer RouterWriter, before []wifi.Profile, modes map[int]int, dhcpBefore bool) error {
	return writer.Authenticate(ctx, func() error {
		identity, after, dhcpAfter, err := readRouterState(ctx, writer)
		if err != nil {
			return err
		}
		if err := requireSupportedExtender(identity); err != nil {
			return err
		}
		if dhcpBefore != dhcpAfter {
			return errors.New("extender DHCP enabled state changed")
		}
		return wifi.VerifyExtenderIoTModes(before, after, modes)
	})
}
