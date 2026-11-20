package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type bandSyncState struct {
	Profiles []wifi.Profile
	LAN      []map[string]any
	Mesh     []map[string]any
}

func readBandSyncState(ctx context.Context, api RouterAPI) (bandSyncState, error) {
	return readBandSyncStateFor(ctx, api, requireSupportedIdentity)
}

// readBandSyncStateFor reads the same guarded snapshot with the device
// identity check chosen by the caller, so the guarded IoT radio restart can
// also run on the supported extender.
func readBandSyncStateFor(ctx context.Context, api RouterAPI, requireIdentity func(router.Identity) error) (bandSyncState, error) {
	var state bandSyncState
	identity, err := api.ReadIdentity(ctx)
	if err != nil {
		return state, err
	}
	if err := requireIdentity(identity); err != nil {
		return state, err
	}
	var wlan wlanResponse
	if err := api.Get(ctx, "/cgi-bin/DAL?oid=wlan", &wlan); err != nil {
		return state, err
	}
	if wlan.Result != "ZCFG_SUCCESS" || len(wlan.Object) == 0 {
		return state, errors.New("invalid WLAN configuration")
	}
	state.Profiles = wlan.Object
	sort.Slice(state.Profiles, func(i, j int) bool { return state.Profiles[i].Index < state.Profiles[j].Index })
	main := map[int]wifi.Profile{}
	seen := map[int]bool{}
	for _, p := range state.Profiles {
		if _, ok := p.Extra["oneSsidEnable"].(bool); !ok {
			return state, errors.New("missing explicit band synchronization flag")
		}
		if seen[p.Index] || p.Index < 1 {
			return state, errors.New("duplicate or invalid WLAN index")
		}
		seen[p.Index] = true
		if p.OneSSIDEnable != state.Profiles[0].OneSSIDEnable {
			return state, errors.New("inconsistent global band synchronization flags")
		}
		if value, ok := p.Extra["oneSsidEnable_ori"]; ok {
			if _, ok := value.(bool); !ok {
				return state, errors.New("invalid original band synchronization flag")
			}
		}
		if p.Index == 1 || p.Index == 5 {
			main[p.Index] = p
		}
	}
	if main[1].Band != "2.4GHz" || main[5].Band != "5GHz" || main[1].Extra["MainSSID"] != true || main[5].Extra["MainSSID"] != true {
		return state, errors.New("expected main WLAN profiles 1 and 5 on their original bands")
	}
	for _, query := range []struct {
		path   string
		target *[]map[string]any
	}{
		{"/cgi-bin/DAL?oid=lan", &state.LAN}, {"/cgi-bin/DAL?oid=wifi_easy_mesh", &state.Mesh},
	} {
		var response struct {
			Result string           `json:"result"`
			Object []map[string]any `json:"Object"`
		}
		if err := api.Get(ctx, query.path, &response); err != nil {
			return state, err
		}
		if response.Result != "ZCFG_SUCCESS" || len(response.Object) == 0 || (query.path == "/cgi-bin/DAL?oid=wifi_easy_mesh" && len(response.Object) != 1) {
			return state, fmt.Errorf("invalid configuration from %s", query.path)
		}
		*query.target = response.Object
	}
	return state, nil
}

func verifyBandSync(before, after bandSyncState, enabled bool, rollback bool) error {
	expected := before
	expected.Profiles = append([]wifi.Profile(nil), before.Profiles...)
	for i := range expected.Profiles {
		expected.Profiles[i].OneSSIDEnable = enabled
		// Extra includes raw copies of known fields. Clone it before changing
		// this read-only verification view, and retain every unknown field.
		extra := make(map[string]any, len(before.Profiles[i].Extra))
		for key, value := range before.Profiles[i].Extra {
			extra[key] = value
		}
		if _, exists := extra["oneSsidEnable_ori"]; exists && !rollback {
			extra["oneSsidEnable_ori"] = enabled
		}
		for _, current := range after.Profiles {
			if current.Index == expected.Profiles[i].Index && validAutomaticChannel(before.Profiles[i], current) {
				extra["channel"] = current.Extra["channel"]
				break
			}
		}
		expected.Profiles[i].Extra = extra
	}
	// Firmware may align band steering with unified-band mode. This permits
	// only that alignment, not any other steering or mesh-role change.
	if !rollback && len(after.Mesh) == 1 && before.Mesh[0]["BandSteeringEnable"] == !enabled && after.Mesh[0]["BandSteeringEnable"] == enabled {
		mesh := make(map[string]any, len(before.Mesh[0]))
		for key, value := range before.Mesh[0] {
			mesh[key] = value
		}
		mesh["BandSteeringEnable"] = enabled
		expected.Mesh = []map[string]any{mesh}
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return errors.New("encode expected band-sync state")
	}
	got, err := json.Marshal(after)
	if err != nil {
		return errors.New("encode current band-sync state")
	}
	if !bytes.Equal(want, got) {
		var wrongFlags []int
		for _, profile := range after.Profiles {
			if profile.OneSSIDEnable != enabled {
				wrongFlags = append(wrongFlags, profile.Index)
			}
		}
		return fmt.Errorf("WLAN control state mismatch (profiles with wrong sync flag: %v; LAN unchanged: %t; expected mesh state: %t; differing fields: %v)", wrongFlags, reflect.DeepEqual(before.LAN, after.LAN), reflect.DeepEqual(expected.Mesh, after.Mesh), controlStateDifferences(want, got))
	}
	return nil
}

// Return field paths only: snapshots may contain credentials, which must never
// enter error output. Bound diagnostics even for unexpectedly large responses.
func controlStateDifferences(want, got []byte) []string {
	var before, after any
	if json.Unmarshal(want, &before) != nil || json.Unmarshal(got, &after) != nil {
		return []string{"state"}
	}
	var paths []string
	var walk func(any, any, string)
	walk = func(a, b any, path string) {
		if len(paths) >= 12 || reflect.DeepEqual(a, b) {
			return
		}
		if left, ok := a.(map[string]any); ok {
			if right, ok := b.(map[string]any); ok {
				keys := map[string]bool{}
				for key := range left {
					keys[key] = true
				}
				for key := range right {
					keys[key] = true
				}
				ordered := make([]string, 0, len(keys))
				for key := range keys {
					ordered = append(ordered, key)
				}
				sort.Strings(ordered)
				for _, key := range ordered {
					next := key
					if path != "" {
						next = path + "." + key
					}
					walk(left[key], right[key], next)
				}
				return
			}
		}
		if left, ok := a.([]any); ok {
			if right, ok := b.([]any); ok {
				count := len(left)
				if len(right) > count {
					count = len(right)
				}
				for i := 0; i < count; i++ {
					var x, y any
					if i < len(left) {
						x = left[i]
					}
					if i < len(right) {
						y = right[i]
					}
					walk(x, y, fmt.Sprintf("%s[%d]", path, i))
				}
				return
			}
		}
		paths = append(paths, path)
	}
	walk(before, after, "")
	return paths
}

func validAutomaticChannel(before, after wifi.Profile) bool {
	if before.Extra["AutoChannelEnable"] != true || after.Extra["AutoChannelEnable"] != true {
		return false
	}
	channels, ok := before.Extra["PossibleChannels"].(string)
	channel, number := after.Extra["channel"].(float64)
	if !ok || !number || channel <= 0 || channel != float64(int(channel)) {
		return false
	}
	for _, candidate := range strings.Split(channels, ",") {
		if candidate == strconv.Itoa(int(channel)) {
			return true
		}
	}
	return false
}

// SetBandSync toggles the global unified-band flag using the General editor's
// payload, preserving existing main WLAN settings. Writes are never replayed.
func (a *App) SetBandSync(ctx context.Context, enabled, yes bool) (ConfigureResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	read := func(target *bandSyncState) error {
		return writer.Authenticate(ctx, func() error {
			var err error
			*target, err = readBandSyncState(ctx, writer)
			return err
		})
	}
	var before bandSyncState
	if err := read(&before); err != nil {
		return ConfigureResult{}, err
	}
	original := before.Profiles[0].OneSSIDEnable
	if original == enabled {
		return ConfigureResult{}, nil
	}
	if enabled {
		for _, profile := range before.Profiles {
			if profile.Extra["wlSubnetState"] == true || (profile.Extra["MinAddress"] != nil && profile.Extra["MinAddress"] != "") {
				return ConfigureResult{}, errors.New("remove SSID subnets before enabling global band synchronization")
			}
		}
	}
	if _, err := buildBandSyncPayload(before.Profiles, enabled, original); err != nil {
		return ConfigureResult{}, err
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return ConfigureResult{}, errors.New("global band synchronization change requires interactive confirmation or --yes")
		}
		ok, err := a.output.Confirm(fmt.Sprintf("Set global Wi-Fi band synchronization to %t, retaining existing network names and credentials?", enabled))
		if err != nil {
			return ConfigureResult{}, err
		}
		if !ok {
			return ConfigureResult{}, errors.New("global band synchronization change was not confirmed")
		}
	}
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return ConfigureResult{}, err
	}
	result := ConfigureResult{BackupDirectory: dir}
	backup, err := json.MarshalIndent(map[string]any{"model": SupportedModel, "firmware": SupportedFirmware, "oneSsidEnable": original}, "", "  ")
	if err != nil {
		return result, err
	}
	if err := store.WriteBackupFile(dir, "band-sync.json", append(backup, '\n')); err != nil {
		return result, err
	}
	if err := writer.Authenticate(ctx, func() error {
		data, err := writer.Download(ctx, "/cgi-bin/Backup_Restore?action=Backup")
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return errors.New("router backup was empty")
		}
		return store.WriteBackupFile(dir, "router.config", data)
	}); err != nil {
		return result, err
	}
	var current bandSyncState
	if err := read(&current); err != nil {
		return result, err
	}
	if !reflect.DeepEqual(before, current) {
		return result, errors.New("router changed during band-sync preflight; no writes attempted")
	}
	attempted, changeErr := a.applyBandSync(ctx, writer, before.Profiles, enabled, original)
	if changeErr == nil {
		changeErr = read(&current)
	}
	if changeErr == nil {
		changeErr = verifyBandSync(before, current, enabled, false)
	}
	if changeErr == nil {
		result.Changed = true
		return result, nil
	}
	if !attempted {
		return result, changeErr
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	readRollback := func() error {
		return writer.Authenticate(rollbackCtx, func() error {
			var err error
			current, err = readBandSyncState(rollbackCtx, writer)
			return err
		})
	}
	rollbackErr := readRollback()
	if rollbackErr == nil && current.Profiles[0].OneSSIDEnable != original {
		result.RollbackAttempted = true
		_, rollbackErr = a.applyBandSync(rollbackCtx, writer, before.Profiles, original, current.Profiles[0].OneSSIDEnable)
		if rollbackErr == nil {
			rollbackErr = readRollback()
		}
	}
	if rollbackErr == nil {
		rollbackErr = verifyBandSync(before, current, original, true)
	}
	if rollbackErr != nil {
		return result, terminalWriteError{message: fmt.Sprintf("%v; rollback failed: %v; backup %s", changeErr, rollbackErr, dir)}
	}
	result.RollbackVerified = true
	return result, terminalWriteError{message: fmt.Sprintf("%v; rollback verified; backup %s", changeErr, dir)}
}

func buildBandSyncPayload(profiles []wifi.Profile, enabled, previous bool) ([]map[string]any, error) {
	var payload []map[string]any
	for _, p := range profiles {
		if p.Index != 1 && p.Index != 5 {
			continue
		}
		mode := ""
		switch p.SecurityMode {
		case "WPA2-Personal":
			mode = "wpa2psk"
		case "WPA3-Personal-Transition":
			mode = "wpa2pskwpa3sae"
		case "WPA3-Personal":
			mode = "wpa3sae"
		default:
			return nil, errors.New("unsupported main WLAN security for preserving General editor settings")
		}
		if err := wifi.ValidatePassphrase(p.PskDisplay); err != nil {
			return nil, errors.New("main WLAN needs a valid existing passphrase; no changes attempted")
		}
		item := map[string]any{
			"Index": p.Index, "wlEnable": p.WLEnable, "oneSsidEnable": enabled, "oneSsidEnable_ori": previous,
			"SSID": p.SSID, "wlHide": p.WLHide, "securityLevel": "MoreSecure", "wpaMode": mode,
			"encryp": p.Encryption, "AutoGenPSK": p.AutoGenPSK, "psk_value": p.PskDisplay, "RekeyingInterval": p.RekeyingInterval,
		}
		for _, key := range []string{"RadiusAccountingPort", "RadiusServerIPAddr", "RadiusServerPort", "RadiusSecret"} {
			if value, exists := p.Extra[key]; exists {
				item[key] = value
			}
		}
		payload = append(payload, item)
	}
	if len(payload) != 2 {
		return nil, errors.New("expected original main WLAN pair")
	}
	if enabled && (payload[0]["SSID"] != payload[1]["SSID"] || payload[0]["psk_value"] != payload[1]["psk_value"] || payload[0]["wpaMode"] != payload[1]["wpaMode"]) {
		return nil, errors.New("cannot enable band synchronization without changing different main WLAN settings")
	}
	return payload, nil
}

func (a *App) applyBandSync(ctx context.Context, writer RouterWriter, profiles []wifi.Profile, enabled, previous bool) (bool, error) {
	payload, err := buildBandSyncPayload(profiles, enabled, previous)
	if err != nil {
		return false, err
	}
	if err := a.authenticateOnly(ctx, writer); err != nil {
		return false, err
	}
	if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", payload); err != nil {
		return true, err
	}
	if err := a.checkWLANAuthenticated(ctx, writer); err != nil {
		return true, err
	}
	return true, nil
}
