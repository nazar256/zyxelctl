package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type extenderBroadcastState struct {
	Identity router.Identity
	Profiles []wifi.Profile
	LAN      []map[string]any
	Mesh     []map[string]any
}

func readExtenderBroadcastState(ctx context.Context, writer RouterWriter) (extenderBroadcastState, error) {
	var state extenderBroadcastState
	identity, err := writer.ReadIdentity(ctx)
	if err != nil {
		return state, err
	}
	if err := requireSupportedExtender(identity); err != nil {
		return state, err
	}
	state.Identity = identity
	var wlan wlanResponse
	if err := writer.Get(ctx, "/cgi-bin/DAL?oid=wlan", &wlan); err != nil {
		return state, err
	}
	if wlan.Result != "ZCFG_SUCCESS" {
		return state, errors.New("invalid extender WLAN response")
	}
	state.Profiles = wlan.Object
	sort.Slice(state.Profiles, func(i, j int) bool { return state.Profiles[i].Index < state.Profiles[j].Index })
	// Validate the existing pair even when it is disabled, so this command can
	// also restore broadcasting without accepting a renamed or unrelated SSID.
	validation := append([]wifi.Profile(nil), state.Profiles...)
	for i := range validation {
		if validation[i].Index == 3 || validation[i].Index == 7 {
			validation[i].WLEnable = true
			validation[i].OneSSIDEnable = true
		}
	}
	if _, err := wifi.ExtenderIoTModes(validation); err != nil {
		return state, err
	}
	for _, query := range []struct {
		path   string
		target *[]map[string]any
	}{
		{"/cgi-bin/DAL?oid=lan", &state.LAN},
		{"/cgi-bin/DAL?oid=wifi_easy_mesh", &state.Mesh},
	} {
		var response struct {
			Result string           `json:"result"`
			Object []map[string]any `json:"Object"`
		}
		if err := writer.Get(ctx, query.path, &response); err != nil {
			return state, err
		}
		if response.Result != "ZCFG_SUCCESS" || len(response.Object) != 1 {
			return state, fmt.Errorf("invalid extender configuration from %s", query.path)
		}
		*query.target = response.Object
	}
	if state.LAN[0]["EnableDHCP"] != false || state.Mesh[0]["EasyMeshEnable"] != true || state.Mesh[0]["CurRole"] != float64(2) {
		return state, errors.New("requires an existing mesh agent with DHCP server disabled")
	}
	return state, nil
}

func iotBroadcasts(profiles []wifi.Profile) map[int]bool {
	values := make(map[int]bool, 2)
	for _, p := range profiles {
		if p.Index == 3 || p.Index == 7 {
			values[p.Index] = p.WLEnable
		}
	}
	return values
}

func verifyExtenderBroadcast(before, after extenderBroadcastState, enabled map[int]bool) error {
	expected := before
	expected.Profiles = append([]wifi.Profile(nil), before.Profiles...)
	for i := range expected.Profiles {
		p := &expected.Profiles[i]
		if value, ok := enabled[p.Index]; ok {
			p.WLEnable = value
		}
		// BSSID and channel are runtime state: a toggled BSS clears or
		// rotates its BSSID and its radio may re-scan channels. Accept the
		// observed values the same way the gateway verification does —
		// BSSID only on requested profiles, a new channel only inside the
		// original automatic-channel list.
		var current *wifi.Profile
		for j := range after.Profiles {
			if after.Profiles[j].Index == p.Index {
				current = &after.Profiles[j]
				break
			}
		}
		if current == nil {
			continue
		}
		extra := make(map[string]any, len(p.Extra))
		for key, value := range p.Extra {
			extra[key] = value
		}
		if _, requested := enabled[p.Index]; requested {
			if value, present := current.Extra["BSSID"]; present {
				extra["BSSID"] = value
			} else {
				delete(extra, "BSSID")
			}
		}
		if validAutomaticChannel(before.Profiles[i], *current) {
			extra["channel"] = current.Extra["channel"]
		}
		p.Extra = extra
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return errors.New("encode expected extender configuration")
	}
	got, err := json.Marshal(after)
	if err != nil {
		return errors.New("encode current extender configuration")
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("extender WLAN, LAN or mesh differs from the requested IoT-only broadcast state: %s", extenderBroadcastDiff(expected, after))
	}
	return nil
}

// extenderBroadcastDiff names the fields where after deviates from expected,
// so a verification failure identifies the drift the firmware introduced.
func extenderBroadcastDiff(expected, after extenderBroadcastState) string {
	var details []string
	diffMap := func(label string, want, got map[string]any) {
		for key, wantValue := range want {
			gotValue, ok := got[key]
			if !ok {
				details = append(details, label+" -"+key)
				continue
			}
			if !reflect.DeepEqual(wantValue, gotValue) {
				details = append(details, label+" "+key)
			}
		}
		for key := range got {
			if _, ok := want[key]; !ok {
				details = append(details, label+" +"+key)
			}
		}
	}
	afterByIndex := map[int]wifi.Profile{}
	for _, p := range after.Profiles {
		afterByIndex[p.Index] = p
	}
	for _, want := range expected.Profiles {
		got, ok := afterByIndex[want.Index]
		label := fmt.Sprintf("wlan[%d]", want.Index)
		if !ok {
			details = append(details, label+" missing")
			continue
		}
		var wantMap, gotMap map[string]any
		if data, err := json.Marshal(want); err == nil {
			_ = json.Unmarshal(data, &wantMap)
		}
		if data, err := json.Marshal(got); err == nil {
			_ = json.Unmarshal(data, &gotMap)
		}
		diffMap(label, wantMap, gotMap)
	}
	for i, wantRow := range expected.LAN {
		if i >= len(after.LAN) {
			details = append(details, fmt.Sprintf("lan[%d] missing", i))
			break
		}
		diffMap(fmt.Sprintf("lan[%d]", i), wantRow, after.LAN[i])
	}
	for i, wantRow := range expected.Mesh {
		if i >= len(after.Mesh) {
			details = append(details, fmt.Sprintf("mesh[%d] missing", i))
			break
		}
		diffMap(fmt.Sprintf("mesh[%d]", i), wantRow, after.Mesh[i])
	}
	if len(details) == 0 {
		return "profile/LAN/mesh row count changed"
	}
	return strings.Join(details, ", ")
}

// SetExtenderIoTBroadcast changes only the two existing IoT BSS enables.
// Global radios, mesh, credentials and all isolation settings are preserved.
func (a *App) SetExtenderIoTBroadcast(ctx context.Context, enabled, yes bool) (ConfigureResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	var before extenderBroadcastState
	read := func(target *extenderBroadcastState) error {
		return writer.Authenticate(ctx, func() error {
			var err error
			*target, err = readExtenderBroadcastState(ctx, writer)
			return err
		})
	}
	if err := read(&before); err != nil {
		return ConfigureResult{}, err
	}
	original := iotBroadcasts(before.Profiles)
	if original[3] == enabled && original[7] == enabled {
		return ConfigureResult{}, nil
	}
	ssid, err := wifi.GuestPairSSID(before.Profiles)
	if err != nil {
		return ConfigureResult{}, err
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return ConfigureResult{}, errors.New("extender IoT broadcast change requires interactive confirmation or --yes")
		}
		ok, err := a.output.Confirm(fmt.Sprintf("Set %q broadcasting on the extender to %t?", ssid, enabled))
		if err != nil {
			return ConfigureResult{}, err
		}
		if !ok {
			return ConfigureResult{}, errors.New("extender IoT broadcast change was not confirmed")
		}
	}
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return ConfigureResult{}, err
	}
	result := ConfigureResult{BackupDirectory: dir}
	backup, err := json.MarshalIndent(map[string]any{"model": before.Identity.Model, "firmware": before.Identity.Firmware, "ssid": ssid, "enabled": original}, "", "  ")
	if err != nil {
		return result, err
	}
	if err := store.WriteBackupFile(dir, "iot-broadcast.json", append(backup, '\n')); err != nil {
		return result, err
	}
	var current extenderBroadcastState
	if err := read(&current); err != nil {
		return result, err
	}
	if !reflect.DeepEqual(before, current) {
		return result, errors.New("extender state changed during preflight; no writes attempted")
	}
	desired := map[int]bool{3: enabled, 7: enabled}
	updates := map[int]bool{}
	for index, value := range original {
		if value != enabled {
			updates[index] = enabled
		}
	}
	attempted, changeErr := a.applyExtenderBroadcast(ctx, writer, updates)
	if changeErr == nil {
		changeErr = read(&current)
	}
	if changeErr == nil {
		changeErr = verifyExtenderBroadcast(before, current, desired)
	}
	if changeErr == nil {
		result.Changed = true
		return result, nil
	}
	if !attempted {
		return result, changeErr
	}
	// A unified-band agent may change both IoT BSSes from one request.
	// Restore the entire original pair after any attempted write, not just the
	// last acknowledged index. Every rollback PUT is still attempted only once.
	result.RollbackAttempted = true
	_, rollbackErr := a.applyExtenderBroadcast(ctx, writer, original)
	if rollbackErr == nil {
		rollbackErr = read(&current)
	}
	if rollbackErr == nil {
		rollbackErr = verifyExtenderBroadcast(before, current, original)
	}
	if rollbackErr != nil {
		return result, terminalWriteError{message: fmt.Sprintf("%v; rollback failed: %v; original IoT broadcast state saved in %s", changeErr, rollbackErr, dir)}
	}
	result.RollbackVerified = true
	return result, terminalWriteError{message: fmt.Sprintf("%v; rollback verified; backup %s", changeErr, dir)}
}

func (a *App) applyExtenderBroadcast(ctx context.Context, writer RouterWriter, values map[int]bool) (bool, error) {
	if err := a.authenticateOnly(ctx, writer); err != nil {
		return false, err
	}
	attempted := false
	for _, index := range []int{7, 3} {
		enabled, ok := values[index]
		if !ok {
			continue
		}
		attempted = true
		// Keep mutations outside Authenticate callbacks, which may be retried.
		if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", map[string]any{"Index": index, "wlEnable": enabled}); err != nil {
			return attempted, fmt.Errorf("set extender IoT profile %d broadcast: %w", index, err)
		}
		if err := a.checkWLANAuthenticated(ctx, writer); err != nil {
			return attempted, err
		}
	}
	return attempted, nil
}
