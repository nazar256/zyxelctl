package app

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type broadcastRouter struct {
	*writeRouter
	profiles     []wifi.Profile
	meshChanged  bool
	normalize    bool
	runtimeChurn bool
	reads        int
	race         bool
	drift        string
}

func (r *broadcastRouter) Get(ctx context.Context, path string, target any) error {
	var value any
	switch path {
	case "/cgi-bin/DAL?oid=wlan":
		r.reads++
		if r.race && r.reads == 2 {
			r.profiles[0].SSID = "concurrent edit"
		}
		if r.putCalls == 2 && r.drift == "other SSID" {
			r.profiles[0].SSID = "unwanted edit"
		}
		if r.putCalls == 2 && r.drift == "unknown field" {
			r.profiles[1].Extra["upRate"] = float64(123)
		}
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": r.profiles}
	case "/cgi-bin/DAL?oid=wifi_easy_mesh":
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"EasyMeshEnable": !(r.meshChanged && r.putCalls > 0), "CurRole": 2}}}
	case "/cgi-bin/DAL?oid=lan":
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"EnableDHCP": r.putCalls == 2 && r.drift == "LAN"}}}
	default:
		return r.writeRouter.Get(ctx, path, target)
	}
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, target)
}

func (r *broadcastRouter) Put(ctx context.Context, path string, payload any) error {
	err := r.writeRouter.Put(ctx, path, payload)
	p := payload.(map[string]any)
	if path != "/cgi-bin/DAL?oid=wlan" || len(p) != 2 {
		return fmt.Errorf("unexpected payload: %v", p)
	}
	for i := range r.profiles {
		if r.profiles[i].Index == p["Index"].(int) && !r.normalize {
			r.profiles[i].WLEnable = p["wlEnable"].(bool)
			if r.runtimeChurn {
				r.profiles[i].Extra["BSSID"] = "02:00:5e:aa:bb:cc"
			}
		}
		// Newer firmware re-scans the radio channel whenever a BSS toggles;
		// the current channel is runtime state, not configuration.
		if r.runtimeChurn {
			r.profiles[i].Extra["channel"] = float64(11)
		}
	}
	return err
}

func newBroadcastApp(t *testing.T) (*App, *broadcastRouter, *backupStore) {
	t.Helper()
	a, w, s, _ := newWriteApp(t)
	p := w.after
	for i := range p {
		p[i].Extra = map[string]any{"MainSSID": p[i].Index == 1}
	}
	w.identity = router.Identity{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b13"}
	w.dhcpBefore = false
	w.dhcpAfter = false
	r := &broadcastRouter{writeRouter: w, profiles: p}
	a.router = r
	return a, r, s
}

func TestExtenderBroadcastDisableEnableAndNoop(t *testing.T) {
	a, r, s := newBroadcastApp(t)
	result, err := a.SetExtenderIoTBroadcast(context.Background(), false, true)
	if err != nil || !result.Changed || r.putCalls != 2 {
		t.Fatalf("disable: %#v %v puts=%d", result, err, r.putCalls)
	}
	if len(s.files["iot-broadcast.json"]) == 0 {
		t.Fatal("missing rollback backup")
	}
	if !reflect.DeepEqual(r.putPayloads, []any{map[string]any{"Index": 7, "wlEnable": false}, map[string]any{"Index": 3, "wlEnable": false}}) {
		t.Fatalf("payloads: %v", r.putPayloads)
	}
	result, err = a.SetExtenderIoTBroadcast(context.Background(), false, true)
	if err != nil || result.Changed || r.putCalls != 2 {
		t.Fatalf("noop: %#v %v", result, err)
	}
	result, err = a.SetExtenderIoTBroadcast(context.Background(), true, true)
	if err != nil || !result.Changed || r.putCalls != 4 {
		t.Fatalf("enable: %#v %v", result, err)
	}
}

func TestExtenderBroadcastToleratesRuntimeBssidAndChannel(t *testing.T) {
	a, r, _ := newBroadcastApp(t)
	r.runtimeChurn = true
	for i := range r.profiles {
		r.profiles[i].Extra["AutoChannelEnable"] = true
		r.profiles[i].Extra["PossibleChannels"] = "1,6,11"
		r.profiles[i].Extra["channel"] = float64(6)
		r.profiles[i].Extra["BSSID"] = "02:00:5e:24:00:01"
	}
	result, err := a.SetExtenderIoTBroadcast(context.Background(), false, true)
	if err != nil || !result.Changed || r.putCalls != 2 {
		t.Fatalf("result=%+v err=%v puts=%d", result, err, r.putCalls)
	}
	for _, p := range r.profiles {
		want := p.Index != 3 && p.Index != 7
		if p.WLEnable != want {
			t.Fatalf("profile %d wlEnable=%v", p.Index, p.WLEnable)
		}
	}
}

func TestExtenderBroadcastRejectsChannelDriftOnFixedChannels(t *testing.T) {
	a, r, _ := newBroadcastApp(t)
	r.runtimeChurn = true
	for i := range r.profiles {
		r.profiles[i].Extra["channel"] = float64(6)
	}
	result, err := a.SetExtenderIoTBroadcast(context.Background(), false, true)
	if err == nil || result.Changed || !result.RollbackAttempted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestExtenderBroadcastPreservesIndependentBands(t *testing.T) {
	a, r, _ := newBroadcastApp(t)
	for i := range r.profiles {
		r.profiles[i].OneSSIDEnable = false
	}
	if _, err := a.SetExtenderIoTBroadcast(context.Background(), false, true); err != nil {
		t.Fatal(err)
	}
	for _, p := range r.profiles {
		if p.OneSSIDEnable {
			t.Fatal("band sync was changed")
		}
	}
}

func TestExtenderBroadcastRefusesUnsafePreflight(t *testing.T) {
	for _, kind := range []string{"router", "renamed", "missing MainSSID", "backup", "race", "confirmation"} {
		t.Run(kind, func(t *testing.T) {
			a, r, s := newBroadcastApp(t)
			yes := true
			switch kind {
			case "router":
				r.identity.Model = SupportedModel
			case "renamed":
				r.profiles[1].SSID = "GuestNet"
			case "missing MainSSID":
				delete(r.profiles[1].Extra, "MainSSID")
			case "backup":
				s.failFile = "iot-broadcast.json"
			case "race":
				r.race = true
			case "confirmation":
				yes = false
				a.output.Interactive = false
			}
			if _, err := a.SetExtenderIoTBroadcast(context.Background(), false, yes); err == nil || r.putCalls != 0 {
				t.Fatalf("unsafe write: err=%v puts=%d", err, r.putCalls)
			}
		})
	}
}

func TestExtenderBroadcastUncertainWriteIsNotReplayed(t *testing.T) {
	a, r, _ := newBroadcastApp(t)
	r.retryAuth = true
	r.putErrors = map[int]error{1: router.ErrUnauthenticated}
	result, err := a.SetExtenderIoTBroadcast(context.Background(), false, true)
	if err == nil || !result.RollbackVerified || r.putCalls != 3 {
		t.Fatalf("result=%#v err=%v puts=%d", result, err, r.putCalls)
	}
	if r.putPayloads[1].(map[string]any)["wlEnable"] != true {
		t.Fatal("uncertain disable replayed instead of rollback")
	}
}

func TestExtenderBroadcastRejectsNormalizationAndMeshChanges(t *testing.T) {
	for _, mesh := range []bool{false, true} {
		a, r, _ := newBroadcastApp(t)
		r.meshChanged = mesh
		r.normalize = !mesh
		result, err := a.SetExtenderIoTBroadcast(context.Background(), false, true)
		if err == nil || !result.RollbackAttempted {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		if !mesh && !result.RollbackVerified {
			t.Fatal("normalization rollback not verified")
		}
		if mesh && result.RollbackVerified {
			t.Fatal("mesh drift falsely accepted")
		}
	}
}

func TestExtenderBroadcastDetectsUnrelatedConfigurationChanges(t *testing.T) {
	for _, kind := range []string{"other SSID", "unknown field", "LAN"} {
		t.Run(kind, func(t *testing.T) {
			a, r, _ := newBroadcastApp(t)
			r.drift = kind
			result, err := a.SetExtenderIoTBroadcast(context.Background(), false, true)
			if err == nil || !result.RollbackAttempted {
				t.Fatalf("unrelated drift accepted: %#v %v", result, err)
			}
		})
	}
}
