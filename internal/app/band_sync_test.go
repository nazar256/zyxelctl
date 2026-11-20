package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type bandSyncRouter struct {
	*writeRouter
	profiles          []wifi.Profile
	mesh              bool
	steering          bool
	reads             int
	race              bool
	drift             string
	rejectBeforeApply bool
}

func (r *bandSyncRouter) Get(ctx context.Context, path string, target any) error {
	var value any
	switch path {
	case "/cgi-bin/DAL?oid=wlan":
		r.reads++
		if r.race && r.reads == 2 {
			r.profiles[1].SSID = "concurrent change"
		}
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": r.profiles}
	case "/cgi-bin/DAL?oid=lan":
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"EnableDHCP": true, "IPAddress": "192.168.1.1", "SubnetMask": "255.255.255.0"}}}
	case "/cgi-bin/DAL?oid=wifi_easy_mesh":
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"EasyMeshEnable": r.mesh, "BandSteeringEnable": r.steering}}}
	default:
		return r.writeRouter.Get(ctx, path, target)
	}
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, target)
}

func (r *bandSyncRouter) Put(ctx context.Context, path string, payload any) error {
	err := r.writeRouter.Put(ctx, path, payload)
	if r.rejectBeforeApply {
		return err
	}
	if r.drift == "ignored" {
		return err
	}
	p, ok := payload.([]map[string]any)
	if !ok || len(p) != 2 || p[0]["Index"] != 1 || p[1]["Index"] != 5 {
		return fmt.Errorf("unexpected band-sync payload")
	}
	enabled := p[0]["oneSsidEnable"].(bool)
	if p[0]["oneSsidEnable_ori"] != !enabled || p[1]["oneSsidEnable_ori"] != !enabled {
		return fmt.Errorf("missing original flag needed by the firmware transition check")
	}
	for _, item := range p {
		if item["SSID"] != "Primary" || item["wlEnable"] != true || item["securityLevel"] != "MoreSecure" || item["wpaMode"] != "wpa2psk" || item["psk_value"] != "unchanged-password" {
			return fmt.Errorf("General editor requires preserved main WLAN settings")
		}
	}
	for i := range r.profiles {
		r.profiles[i].OneSSIDEnable = enabled
		r.profiles[i].Extra["oneSsidEnable_ori"] = enabled
	}
	r.steering = enabled
	if r.putCalls == 1 {
		switch r.drift {
		case "SSID":
			r.profiles[1].SSID = "changed unexpectedly"
		case "unknown":
			r.profiles[1].Extra["upRate"] = float64(10)
		case "mesh":
			r.mesh = false
		}
	}
	return err
}

func newBandSyncApp(t *testing.T) (*App, *bandSyncRouter, *backupStore) {
	a, w, s, _ := newWriteApp(t)
	_, p := writeProfiles()
	p[0].Band = "2.4GHz"
	p[0].OneSSIDEnable = true
	p = append(p, wifi.Profile{Index: 5, Band: "5GHz", WLEnable: true, OneSSIDEnable: true, SSID: "Primary", SecurityMode: "WPA2-Personal"})
	for i := range p {
		p[i].Extra = map[string]any{"MainSSID": p[i].Index == 1 || p[i].Index == 5, "oneSsidEnable_ori": true}
		if p[i].Index == 1 || p[i].Index == 5 {
			p[i].PskDisplay = "unchanged-password"
		}
	}
	r := &bandSyncRouter{writeRouter: w, profiles: p, mesh: true, steering: true}
	a.router = r
	return a, r, s
}

func TestBandSyncReversibleAndNoop(t *testing.T) {
	a, r, s := newBandSyncApp(t)
	result, err := a.SetBandSync(context.Background(), false, true)
	if err != nil || !result.Changed || r.putCalls != 1 {
		t.Fatalf("disable: %#v %v puts=%d", result, err, r.putCalls)
	}
	if len(s.files["band-sync.json"]) == 0 {
		t.Fatal("missing password-free backup")
	}
	if _, err := a.SetBandSync(context.Background(), false, true); err != nil || r.putCalls != 1 {
		t.Fatalf("noop: %v puts=%d", err, r.putCalls)
	}
	result, err = a.SetBandSync(context.Background(), true, true)
	if err != nil || !result.Changed || r.putCalls != 2 {
		t.Fatalf("enable: %#v %v", result, err)
	}
}

func TestBandSyncGuardsAndConcurrentChanges(t *testing.T) {
	for _, kind := range []string{"firmware", "main profile", "inconsistent flag", "backup", "race", "confirmation", "unsupported security", "missing password"} {
		t.Run(kind, func(t *testing.T) {
			a, r, s := newBandSyncApp(t)
			yes := true
			switch kind {
			case "firmware":
				r.identity.Firmware = "unsupported"
			case "main profile":
				r.profiles[0].Extra["MainSSID"] = false
			case "inconsistent flag":
				r.profiles[1].OneSSIDEnable = false
			case "backup":
				s.failFile = "band-sync.json"
			case "race":
				r.race = true
			case "confirmation":
				yes = false
				a.output.Interactive = false
			case "unsupported security":
				r.profiles[0].SecurityMode = "None"
			case "missing password":
				r.profiles[0].PskDisplay = ""
			}
			if _, err := a.SetBandSync(context.Background(), false, yes); err == nil || r.putCalls != 0 {
				t.Fatalf("unsafe preflight err=%v puts=%d", err, r.putCalls)
			}
		})
	}
}

func TestBandSyncRejectsCollateralChangesAndIgnoredFlag(t *testing.T) {
	for _, kind := range []string{"SSID", "unknown", "mesh", "ignored"} {
		t.Run(kind, func(t *testing.T) {
			a, r, _ := newBandSyncApp(t)
			r.drift = kind
			result, err := a.SetBandSync(context.Background(), false, true)
			if err == nil || (!result.RollbackAttempted && !result.RollbackVerified) {
				t.Fatalf("drift accepted %#v %v", result, err)
			}
			if kind == "ignored" && !result.RollbackVerified {
				t.Fatalf("ignored toggle rollback not verified: %v", err)
			}
		})
	}
}

func TestBandSyncUncertainWriteNeverReplayed(t *testing.T) {
	a, r, _ := newBandSyncApp(t)
	r.retryAuth = true
	r.putErrors = map[int]error{1: router.ErrUnauthenticated}
	result, err := a.SetBandSync(context.Background(), false, true)
	if err == nil || !result.RollbackVerified || r.putCalls != 2 {
		t.Fatalf("%#v err=%v puts=%d", result, err, r.putCalls)
	}
	if r.putPayloads[1].([]map[string]any)[0]["oneSsidEnable"] != true {
		t.Fatal("uncertain write replayed")
	}
}

func TestBandSyncRejectedWriteVerifiesBaselineWithoutRestorationPut(t *testing.T) {
	a, r, _ := newBandSyncApp(t)
	r.rejectBeforeApply = true
	r.putErrors = map[int]error{1: router.ErrUnauthenticated}
	r.retryAuth = true
	result, err := a.SetBandSync(context.Background(), false, true)
	if err == nil || !result.RollbackVerified || result.RollbackAttempted || r.putCalls != 1 {
		t.Fatalf("unneeded rollback write: %#v %v puts=%d", result, err, r.putCalls)
	}
}

func TestBandSyncVerificationDistinguishesAutomaticChannelSelection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		auto    bool
		channel float64
		wantOK  bool
	}{
		{"automatic supported channel", true, 48, true},
		{"fixed channel", false, 48, false},
		{"channel outside allowed set", true, 149, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, r, _ := newBandSyncApp(t)
			for i := range r.profiles {
				r.profiles[i].Extra["AutoChannelEnable"] = tc.auto
				r.profiles[i].Extra["PossibleChannels"] = "36,40,44,48,52"
				r.profiles[i].Extra["channel"] = float64(52)
			}
			var before bandSyncState
			if err := r.Authenticate(context.Background(), func() error { var err error; before, err = readBandSyncState(context.Background(), r); return err }); err != nil {
				t.Fatal(err)
			}
			if _, err := a.applyBandSync(context.Background(), r, before.Profiles, false, true); err != nil {
				t.Fatal(err)
			}
			for i := range r.profiles {
				r.profiles[i].Extra["channel"] = tc.channel
			}
			after, err := readBandSyncState(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyBandSync(before, after, false, false); (err == nil) != tc.wantOK {
				t.Fatalf("verify=%v wantOK=%t", err, tc.wantOK)
			}
		})
	}
}

func TestBandSyncRefusesMergingAnActiveSSIDSubnet(t *testing.T) {
	a, r, _ := newBandSyncApp(t)
	for i := range r.profiles {
		r.profiles[i].OneSSIDEnable = false
	}
	r.profiles[1].Extra["wlSubnetState"] = true
	if _, err := a.SetBandSync(context.Background(), true, true); err == nil || r.putCalls != 0 {
		t.Fatalf("active subnet merge accepted: %v puts=%d", err, r.putCalls)
	}
}

func TestWLANControlDiagnosticsIdentifyFieldsWithoutValues(t *testing.T) {
	a, r, _ := newBandSyncApp(t)
	r.drift = "SSID"
	_, err := a.SetBandSync(context.Background(), false, true)
	if err == nil || !strings.Contains(err.Error(), ".SSID") || strings.Contains(err.Error(), "changed unexpectedly") || strings.Contains(err.Error(), "unchanged-password") {
		t.Fatalf("unsafe or unhelpful diagnostic: %v", err)
	}
}
