package app

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type radioRestartRouter struct {
	*writeRouter
	profiles      []wifi.Profile
	lan           []map[string]any
	mesh          []map[string]any
	wipeOnDisable bool
}

func (r *radioRestartRouter) Get(ctx context.Context, path string, target any) error {
	var value any
	switch path {
	case "/cgi-bin/DAL?oid=wlan":
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": r.profiles}
	case "/cgi-bin/DAL?oid=lan":
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": r.lan}
	case "/cgi-bin/DAL?oid=wifi_easy_mesh":
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": r.mesh}
	default:
		return r.writeRouter.Get(ctx, path, target)
	}
	if !r.authenticated {
		return router.ErrUnauthenticated
	}
	*r.events = append(*r.events, "get:"+path)
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, target)
}

func (r *radioRestartRouter) Put(ctx context.Context, path string, payload any) error {
	err := r.writeRouter.Put(ctx, path, payload)
	p, _ := payload.(map[string]any)
	if path != "/cgi-bin/DAL?oid=wlan" || p == nil {
		return fmt.Errorf("unexpected PUT %s: %#v", path, payload)
	}
	index, _ := p["Index"].(int)
	for i := range r.profiles {
		if r.profiles[i].Index != index {
			continue
		}
		if enable, ok := p["wlEnable"].(bool); ok {
			r.profiles[i].WLEnable = enable
			if r.wipeOnDisable && !enable {
				for _, k := range []string{"wlSubnetState", "MinAddress", "MaxAddress", "SubnetMask", "LANIP", "Interface"} {
					delete(r.profiles[i].Extra, k)
				}
			}
		}
		// A full restore payload carries the guest/subnet fields back.
		for _, k := range []string{"wlSubnetState", "MinAddress", "MaxAddress", "SubnetMask", "LANIP", "Interface"} {
			if v, ok := p[k]; ok {
				r.profiles[i].Extra[k] = v
			}
		}
	}
	return err
}

func radioProfiles() []wifi.Profile {
	return []wifi.Profile{
		{Index: 1, Band: "2.4GHz", WLEnable: true, SSID: "Primary", SecurityMode: "WPA2-Personal", Extra: map[string]any{"MainSSID": true}},
		{Index: 5, Band: "5GHz", WLEnable: true, SSID: "Primary5", SecurityMode: "WPA2-Personal", Extra: map[string]any{"MainSSID": true}},
		{Index: 3, Band: "2.4GHz", WLEnable: true, SSID: "IoT-Lab", SecurityMode: "WPA2-Personal", PskDisplay: "iot-password", BSSIDIsolation: true, Extra: map[string]any{"MainSSID": false, "BSSID": "02:00:5e:24:00:01", "wlSubnetState": true, "MinAddress": "10.99.0.2", "MaxAddress": "10.99.0.100", "SubnetMask": "255.255.255.0", "LANIP": "10.99.0.1", "Interface": "WiFi.SSID.3"}},
		{Index: 7, Band: "5GHz", WLEnable: false, SSID: "IoT-Lab", SecurityMode: "WPA2-Personal", BSSIDIsolation: true, Extra: map[string]any{"MainSSID": false, "BSSID": "02:00:5e:50:00:01"}},
	}
}

func newRadioRestartApp(t *testing.T, confirm func(string) (bool, error)) (*App, *radioRestartRouter, *backupStore) {
	t.Helper()
	events := &[]string{}
	base := &writeRouter{identity: router.Identity{Model: SupportedModel, Firmware: SupportedFirmware}, events: events, authenticated: true}
	r := &radioRestartRouter{
		writeRouter: base,
		profiles:    radioProfiles(),
		lan:         []map[string]any{{"EnableDHCP": true, "IPAddress": "192.168.1.1", "SubnetMask": "255.255.255.0"}},
		mesh:        []map[string]any{{"EasyMeshEnable": true, "CurRole": 4}},
	}
	store := &backupStore{root: filepath.Join(t.TempDir(), "backup"), events: events}
	output := Output{
		Interactive: true,
		Confirm:     confirm,
		Now:         func() time.Time { return time.Date(2024, 1, 2, 9, 0, 0, 0, time.UTC) },
		Sleep:       func(time.Duration) {},
	}
	return New(r, store, output), r, store
}

func TestRestartIoTRadioBouncesOnlyEnabledIoTProfile(t *testing.T) {
	a, r, store := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	result, err := a.RestartIoTRadio(context.Background(), true)
	if err != nil || !result.Changed || result.RollbackAttempted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(result.Restarted) != 1 || result.Restarted[0] != 3 || result.BackupDirectory != store.root {
		t.Fatalf("result=%+v", result)
	}
	if r.putCalls != 2 || r.wlCheckCalls != 2 {
		t.Fatalf("puts=%d wlchecks=%d", r.putCalls, r.wlCheckCalls)
	}
	disable := r.putPayloads[0].(map[string]any)
	if len(disable) != 2 || disable["Index"] != 3 || disable["wlEnable"] != false {
		t.Fatalf("disable payload = %#v", disable)
	}
	enable := r.putPayloads[1].(map[string]any)
	if enable["Index"] != 3 || enable["wlEnable"] != true || enable["SSID"] != "IoT-Lab" || enable["subnetObjAction"] != "PUT" {
		t.Fatalf("enable payload = %#v", enable)
	}
	for _, p := range r.profiles {
		want := p.Index != 7
		if p.WLEnable != want {
			t.Fatalf("profile %d wlEnable=%v", p.Index, p.WLEnable)
		}
	}
	if len(store.files) != 3 {
		t.Fatalf("backup files=%v", store.files)
	}
}

func TestRestartIoTRadioBouncesBothBandsWhenEnabled(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	for i := range r.profiles {
		if r.profiles[i].Index == 7 {
			r.profiles[i].WLEnable = true
		}
	}
	result, err := a.RestartIoTRadio(context.Background(), true)
	if err != nil || len(result.Restarted) != 2 || r.putCalls != 4 {
		t.Fatalf("result=%+v err=%v puts=%d", result, err, r.putCalls)
	}
}

func TestRestartIoTRadioPreflightGuards(t *testing.T) {
	for _, name := range []string{"wrong firmware", "renamed SSID", "missing MainSSID", "isolation drift", "both disabled", "unconfirmed"} {
		t.Run(name, func(t *testing.T) {
			a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
			yes := true
			switch name {
			case "wrong firmware":
				r.identity.Firmware = "other"
			case "renamed SSID":
				r.profiles[2].SSID = "Other"
			case "missing MainSSID":
				r.profiles[2].Extra["MainSSID"] = true
			case "isolation drift":
				r.profiles[2].BSSIDIsolation = false
			case "both disabled":
				r.profiles[2].WLEnable = false
			case "unconfirmed":
				yes = false
				a, r, _ = newRadioRestartApp(t, func(string) (bool, error) { return false, nil })
			}
			_, err := a.RestartIoTRadio(context.Background(), yes)
			if err == nil || r.putCalls != 0 {
				t.Fatalf("err=%v puts=%d", err, r.putCalls)
			}
		})
	}
}

func TestRestartIoTRadioRebuildsSubnetDroppedByDisable(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	// Firmware drops the subnet object when the 2.4 GHz guest profile is
	// disabled; the re-enable step must rebuild it, not roll back.
	r.wipeOnDisable = true
	result, err := a.RestartIoTRadio(context.Background(), true)
	if err != nil || !result.Changed || result.RollbackAttempted || len(result.Restarted) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if r.putCalls != 2 {
		t.Fatalf("puts=%d", r.putCalls)
	}
	enable := r.putPayloads[1].(map[string]any)
	if enable["Index"] != 3 || enable["SSID"] != "IoT-Lab" || enable["wlEnable"] != true || enable["subnetObjAction"] != "POST" || enable["MinAddress"] != "10.99.0.2" {
		t.Fatalf("enable payload=%#v", enable)
	}
	if !r.profiles[2].WLEnable || r.profiles[2].Extra["MinAddress"] != "10.99.0.2" {
		t.Fatalf("profile 3 not restored: %#v", r.profiles[2].Extra)
	}
}

func TestRestartIoTRadioOnExtenderBouncesOnlyEnabledGuestProfile(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	r.identity = router.Identity{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b13"}
	// The extender guest pair has no dedicated subnet object.
	for i := range r.profiles {
		if r.profiles[i].Index == 3 {
			for _, key := range iotSubnetFields {
				delete(r.profiles[i].Extra, key)
			}
		}
	}
	result, err := a.RestartIoTRadio(context.Background(), true)
	if err != nil || !result.Changed || result.RollbackAttempted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(result.Restarted) != 1 || result.Restarted[0] != 3 || r.putCalls != 2 {
		t.Fatalf("result=%+v puts=%d", result, r.putCalls)
	}
	enable := r.putPayloads[1].(map[string]any)
	if enable["Index"] != 3 || enable["wlEnable"] != true || enable["SSID"] != "IoT-Lab" || enable["subnetObjAction"] != nil {
		t.Fatalf("enable payload = %#v", enable)
	}
	want := map[int]bool{1: true, 3: true, 5: true, 7: false}
	for _, p := range r.profiles {
		if p.WLEnable != want[p.Index] {
			t.Fatalf("profile %d wlEnable=%v", p.Index, p.WLEnable)
		}
	}
}

func TestRestartIoTRadioRejectsUnsupportedDevice(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	r.identity = router.Identity{Model: "WX5600-T0", Firmware: "other"}
	if _, err := a.RestartIoTRadio(context.Background(), true); err == nil || r.putCalls != 0 {
		t.Fatalf("err=%v puts=%d", err, r.putCalls)
	}
}

func TestRestartIoTRadioRestoresAfterUncertainWrite(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	r.putErrors = map[int]error{1: fmt.Errorf("connection lost after write")}
	result, err := a.RestartIoTRadio(context.Background(), true)
	if err == nil || !result.RollbackAttempted || !result.RollbackVerified {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	// First PUT "failed" but landed (fixture applies it): profile was disabled
	// and must have been restored to enabled.
	if !r.profiles[2].WLEnable {
		t.Fatal("uncertain disable was not rolled back")
	}
}
