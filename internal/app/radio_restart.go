package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type RadioRestartResult struct {
	ConfigureResult
	Restarted []int `json:"restarted"`
}

// iotGuestPair returns the IoT guest profile pair (indexes 3 and 7) when both
// still form one WPA2 Home Guest network, regardless of their enable state.
func iotGuestPair(state bandSyncState) (map[int]wifi.Profile, string, error) {
	ssid, err := wifi.GuestPairSSID(state.Profiles)
	if err != nil {
		return nil, "", err
	}
	pair := make(map[int]wifi.Profile, 2)
	for _, p := range state.Profiles {
		if p.Index == 3 || p.Index == 7 {
			pair[p.Index] = p
		}
	}
	for index, band := range map[int]string{3: "2.4GHz", 7: "5GHz"} {
		p, ok := pair[index]
		if !ok || p.SSID != ssid || p.Band != band || p.SecurityMode != "WPA2-Personal" || p.IsolationEnable || !p.BSSIDIsolation {
			return nil, "", errors.New("expected the IoT guest pair on profiles 3 and 7")
		}
	}
	return pair, ssid, nil
}

// iotRadioTargets returns the enabled members of the IoT guest profile pair.
// Disabled members keep their configuration and stay off.
func iotRadioTargets(state bandSyncState) (map[int]wifi.Profile, string, error) {
	pair, ssid, err := iotGuestPair(state)
	if err != nil {
		return nil, "", err
	}
	targets := make(map[int]wifi.Profile, 2)
	for index, p := range pair {
		if p.WLEnable {
			targets[index] = p
		}
	}
	if len(targets) == 0 {
		return nil, "", errors.New("no enabled IoT guest profile to restart")
	}
	return targets, ssid, nil
}

// verifyIoTRadio compares the complete WLAN/LAN/mesh state. For each profile
// listed in enabled it expects that enable state and accepts the current
// runtime BSSID; automatic channel selection is normalized by verifyBandSync.
// Firmware drops the subnet object when the 2.4 GHz guest profile is disabled,
// so a disabled expectation also tolerates removed subnet fields. Absent
// subnet keys and explicit empty values are equivalent: devices without a
// guest subnet may store explicit nulls after a profile restore.
func verifyIoTRadio(before, after bandSyncState, enabled map[int]bool) error {
	data, err := json.Marshal(before)
	if err != nil {
		return err
	}
	var expected bandSyncState
	if err := json.Unmarshal(data, &expected); err != nil {
		return err
	}
	dropEmpty := func(profiles []wifi.Profile) {
		for i := range profiles {
			for _, key := range iotSubnetFields {
				switch profiles[i].Extra[key] {
				case nil, false, "":
					delete(profiles[i].Extra, key)
				}
			}
		}
	}
	dropEmpty(expected.Profiles)
	dropEmpty(after.Profiles)
	for i := range expected.Profiles {
		p := &expected.Profiles[i]
		want, ok := enabled[p.Index]
		if !ok {
			continue
		}
		p.WLEnable = want
		var currentProfile *wifi.Profile
		for j := range after.Profiles {
			if after.Profiles[j].Index == p.Index {
				currentProfile = &after.Profiles[j]
				break
			}
		}
		if currentProfile == nil {
			continue
		}
		if value, present := currentProfile.Extra["BSSID"]; present {
			p.Extra["BSSID"] = value
		} else {
			delete(p.Extra, "BSSID")
		}
		if !want && p.Index == 3 {
			for _, key := range iotSubnetFields {
				if _, present := currentProfile.Extra[key]; !present {
					delete(p.Extra, key)
				}
			}
		}
	}
	return verifyBandSync(expected, after, before.Profiles[0].OneSSIDEnable, true)
}

func iotRadioRestorePayload(original, current wifi.Profile) (map[string]any, error) {
	if original.Index != 3 {
		return map[string]any{"Index": original.Index, "wlEnable": original.WLEnable}, nil
	}
	config, err := currentIoTSubnet(original)
	if err != nil {
		return nil, err
	}
	action := ""
	if config != nil {
		currentConfig, err := currentIoTSubnet(current)
		if err != nil {
			return nil, err
		}
		action = "POST"
		if currentConfig != nil {
			action = "PUT"
		}
	}
	payload := buildIoTSubnetPayload(original, original.WLEnable, config, action)
	if config == nil {
		// The peer-access flow exercises this explicit null shape.
		payload["subnetObjAction"] = nil
	}
	return payload, nil
}

// restoreIoTRadioProfiles reverts each attempted IoT profile to its
// before-state, rebuilding profile 3's subnet object when the original had
// one. Every restore PUT is attempted at most once.
func (a *App) restoreIoTRadioProfiles(read func(context.Context, *bandSyncState) error, writer RouterWriter, before, current bandSyncState, attempted []int) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	latest := current
	if err := read(rollbackCtx, &latest); err != nil {
		return err
	}
	var restores []map[string]any
	for _, index := range attempted {
		var original, currentProfile *wifi.Profile
		for i := range before.Profiles {
			if before.Profiles[i].Index == index {
				original = &before.Profiles[i]
			}
		}
		for i := range latest.Profiles {
			if latest.Profiles[i].Index == index {
				currentProfile = &latest.Profiles[i]
			}
		}
		if original == nil || currentProfile == nil {
			return fmt.Errorf("IoT profile %d missing during restore", index)
		}
		payload, err := iotRadioRestorePayload(*original, *currentProfile)
		if err != nil {
			return err
		}
		restores = append(restores, payload)
	}
	for _, payload := range restores {
		if err := a.authenticateOnly(rollbackCtx, writer); err != nil {
			return err
		}
		if err := writer.Put(rollbackCtx, "/cgi-bin/DAL?oid=wlan", payload); err != nil {
			return fmt.Errorf("restore IoT profile %v: %w", payload["Index"], err)
		}
		if err := a.checkWLANAuthenticated(rollbackCtx, writer); err != nil {
			return err
		}
	}
	if err := read(rollbackCtx, &latest); err != nil {
		return err
	}
	originalEnabled := make(map[int]bool, len(attempted))
	for _, index := range attempted {
		for _, p := range before.Profiles {
			if p.Index == index {
				originalEnabled[index] = p.WLEnable
			}
		}
	}
	return verifyIoTRadio(before, latest, originalEnabled)
}

// RestartIoTRadio bounces only the enabled IoT guest BSSes on the connected
// device (gateway or supported extender) so clients reassociate and renew
// DHCP. Other networks, radios and the device itself are not restarted; a
// disabled pair member stays off.
func (a *App) RestartIoTRadio(ctx context.Context, yes bool) (RadioRestartResult, error) {
	result := RadioRestartResult{Restarted: []int{}}
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
	requireIdentity := requireSupportedIdentity
	deviceName := "gateway"
	if identity.Model != SupportedModel {
		requireIdentity = requireSupportedExtender
		deviceName = "extender"
	}
	read := func(ctx context.Context, target *bandSyncState) error {
		return writer.Authenticate(ctx, func() error {
			var err error
			*target, err = readBandSyncStateFor(ctx, writer, requireIdentity)
			return err
		})
	}
	var before bandSyncState
	if err := read(ctx, &before); err != nil {
		return result, err
	}
	targets, ssid, err := iotRadioTargets(before)
	if err != nil {
		return result, err
	}
	if p3, ok := targets[3]; ok {
		if err := wifi.ValidatePassphrase(p3.PskDisplay); err != nil {
			return result, errors.New("existing IoT passphrase is unavailable")
		}
	}
	indices := make([]int, 0, len(targets))
	for index := range targets {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return result, errors.New("IoT Wi-Fi restart requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Restart only the %q Wi-Fi network on the %s (disable then re-enable profiles %v)? Clients must reassociate and renew leases.", ssid, deviceName, indices))
		if err != nil {
			return result, err
		}
		if !confirmed {
			return result, errors.New("IoT Wi-Fi restart was not confirmed")
		}
	}
	pair := make([]wifi.Profile, 0, 2)
	for _, index := range []int{3, 7} {
		for _, p := range before.Profiles {
			if p.Index == index {
				pair = append(pair, p)
			}
		}
	}
	dir, err := a.createChangeBackup(ctx, writer, store, identity, pair)
	if err != nil {
		return result, err
	}
	result.BackupDirectory = dir
	var current bandSyncState
	if err := read(ctx, &current); err != nil {
		return result, err
	}
	if err := verifyIoTRadio(before, current, nil); err != nil {
		return result, fmt.Errorf("router changed during IoT restart preflight: %w", err)
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
	changeErr := error(nil)
	for _, index := range indices {
		if err := putPayload(ctx, map[string]any{"Index": index, "wlEnable": false}); err != nil {
			changeErr = err
			break
		}
		a.output.Sleep(3 * time.Second)
		if err := read(ctx, &current); err != nil {
			changeErr = err
			break
		}
		if err := verifyIoTRadio(before, current, map[int]bool{index: false}); err != nil {
			changeErr = fmt.Errorf("disabled IoT profile %d left unexpected state: %w", index, err)
			break
		}
		// Re-enable restores the full profile: disabling profile 3 drops its
		// subnet object, so the enable step rebuilds it when needed.
		var original, currentProfile *wifi.Profile
		for i := range before.Profiles {
			if before.Profiles[i].Index == index {
				original = &before.Profiles[i]
			}
		}
		for i := range current.Profiles {
			if current.Profiles[i].Index == index {
				currentProfile = &current.Profiles[i]
			}
		}
		if original == nil || currentProfile == nil {
			changeErr = fmt.Errorf("IoT profile %d missing during restart", index)
			break
		}
		payload, err := iotRadioRestorePayload(*original, *currentProfile)
		if err != nil {
			changeErr = err
			break
		}
		if err := putPayload(ctx, payload); err != nil {
			changeErr = err
			break
		}
		result.Restarted = append(result.Restarted, index)
	}
	if changeErr == nil {
		changeErr = read(ctx, &current)
	}
	if changeErr == nil {
		restored := make(map[int]bool, len(indices))
		for _, index := range indices {
			restored[index] = true
		}
		changeErr = verifyIoTRadio(before, current, restored)
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
