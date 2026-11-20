package app

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nazar256/zyxelctl/internal/wifi"
)

func enableAllProfiles(r *radioRestartRouter) {
	for i := range r.profiles {
		r.profiles[i].WLEnable = true
	}
}

func disableGuestPair(r *radioRestartRouter) {
	for i := range r.profiles {
		if r.profiles[i].Index == 3 || r.profiles[i].Index == 7 {
			r.profiles[i].WLEnable = false
		}
		if r.profiles[i].Index == 3 {
			for _, key := range iotSubnetFields {
				delete(r.profiles[i].Extra, key)
			}
		}
	}
}

func TestIoTBroadcastDisablesOnlyEnabledGuestProfiles(t *testing.T) {
	a, r, store := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	r.wipeOnDisable = true
	result, err := a.SetIoTBroadcast(context.Background(), false, true)
	if err != nil || !result.Changed || result.RollbackAttempted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if r.putCalls != 1 || r.wlCheckCalls != 1 {
		t.Fatalf("puts=%d wlchecks=%d", r.putCalls, r.wlCheckCalls)
	}
	disable := r.putPayloads[0].(map[string]any)
	if len(disable) != 2 || disable["Index"] != 3 || disable["wlEnable"] != false {
		t.Fatalf("disable payload = %#v", disable)
	}
	for _, p := range r.profiles {
		want := p.Index != 3 && p.Index != 7
		if p.WLEnable != want {
			t.Fatalf("profile %d wlEnable=%v", p.Index, p.WLEnable)
		}
	}
	if len(store.files) != 3 {
		t.Fatalf("backup files=%v", store.files)
	}
}

func TestIoTBroadcastDisablesBothBands(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	enableAllProfiles(r)
	r.wipeOnDisable = true
	result, err := a.SetIoTBroadcast(context.Background(), false, true)
	if err != nil || !result.Changed || r.putCalls != 2 {
		t.Fatalf("result=%+v err=%v puts=%d", result, err, r.putCalls)
	}
	for i, index := range []int{3, 7} {
		payload := r.putPayloads[i].(map[string]any)
		if len(payload) != 2 || payload["Index"] != index || payload["wlEnable"] != false {
			t.Fatalf("payload %d = %#v", i, payload)
		}
	}
}

func TestIoTBroadcastAlreadyMatchingIsNoop(t *testing.T) {
	a, r, store := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	disableGuestPair(r)
	result, err := a.SetIoTBroadcast(context.Background(), false, true)
	if err != nil || result.Changed || r.putCalls != 0 || len(store.files) != 0 {
		t.Fatalf("result=%+v err=%v puts=%d files=%v", result, err, r.putCalls, store.files)
	}
}

func TestIoTBroadcastEnableRestoresDisabledPair(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	disableGuestPair(r)
	result, err := a.SetIoTBroadcast(context.Background(), true, true)
	if err != nil || !result.Changed || r.putCalls != 2 {
		t.Fatalf("result=%+v err=%v puts=%d", result, err, r.putCalls)
	}
	enable3 := r.putPayloads[0].(map[string]any)
	if enable3["Index"] != 3 || enable3["wlEnable"] != true || enable3["SSID"] != "IoT-Lab" || enable3["subnetObjAction"] != nil {
		t.Fatalf("enable payload 3 = %#v", enable3)
	}
	enable7 := r.putPayloads[1].(map[string]any)
	if len(enable7) != 2 || enable7["Index"] != 7 || enable7["wlEnable"] != true {
		t.Fatalf("enable payload 7 = %#v", enable7)
	}
	for _, p := range r.profiles {
		if !p.WLEnable {
			t.Fatalf("profile %d stayed disabled", p.Index)
		}
	}
}

func TestIoTBroadcastEnableNeedsPassphraseForGuestPayload(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	disableGuestPair(r)
	r.profiles[2].PskDisplay = ""
	if _, err := a.SetIoTBroadcast(context.Background(), true, true); err == nil || r.putCalls != 0 {
		t.Fatalf("err=%v puts=%d", err, r.putCalls)
	}
}

func TestIoTBroadcastPreflightGuards(t *testing.T) {
	for _, name := range []string{"wrong firmware", "renamed SSID", "isolation drift", "unconfirmed"} {
		t.Run(name, func(t *testing.T) {
			a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
			yes := true
			switch name {
			case "wrong firmware":
				r.identity.Firmware = "other"
			case "renamed SSID":
				r.profiles[2].SSID = "Other"
			case "isolation drift":
				r.profiles[2].BSSIDIsolation = false
			case "unconfirmed":
				yes = false
				a, r, _ = newRadioRestartApp(t, func(string) (bool, error) { return false, nil })
			}
			if _, err := a.SetIoTBroadcast(context.Background(), false, yes); err == nil || r.putCalls != 0 {
				t.Fatalf("err=%v puts=%d", err, r.putCalls)
			}
		})
	}
}

func TestIoTBroadcastRestoresAfterUncertainWrite(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	r.wipeOnDisable = true
	r.putErrors = map[int]error{1: errors.New("connection lost after write")}
	result, err := a.SetIoTBroadcast(context.Background(), false, true)
	if err == nil || !result.RollbackAttempted || !result.RollbackVerified {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !r.profiles[2].WLEnable || r.profiles[2].Extra["MinAddress"] != "10.99.0.2" {
		t.Fatalf("uncertain disable was not rolled back: %#v", r.profiles[2].Extra)
	}
}

func TestIoTBroadcastEnableFailureRestoresOriginalDisable(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	disableGuestPair(r)
	r.putErrors = map[int]error{1: fmt.Errorf("connection lost after write")}
	result, err := a.SetIoTBroadcast(context.Background(), true, true)
	if err == nil || !result.RollbackAttempted || !result.RollbackVerified {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if r.profiles[2].WLEnable {
		t.Fatal("uncertain enable was not rolled back")
	}
}

func TestIoTBroadcastDelegatesToExtender(t *testing.T) {
	for _, firmware := range []string{"V5.70(ACDW.0)b13", "V5.70(ACDW.0)b27"} {
		a, r, _ := newBroadcastApp(t)
		r.identity.Firmware = firmware
		result, err := a.SetIoTBroadcast(context.Background(), false, true)
		if err != nil || !result.Changed || r.putCalls != 2 {
			t.Fatalf("firmware %s: result=%+v err=%v puts=%d", firmware, result, err, r.putCalls)
		}
		for i, index := range []int{7, 3} {
			payload := r.putPayloads[i].(map[string]any)
			if payload["Index"] != index || payload["wlEnable"] != false {
				t.Fatalf("firmware %s: payload %d = %#v", firmware, i, payload)
			}
		}
	}
}

func TestIoTBroadcastRejectsUnsupportedDevice(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	r.identity.Model = "WX5600-T0"
	r.identity.Firmware = "other"
	if _, err := a.SetIoTBroadcast(context.Background(), false, true); err == nil || r.putCalls != 0 {
		t.Fatalf("err=%v puts=%d", err, r.putCalls)
	}
}

func TestIoTBroadcastLeavesOtherProfilesAlone(t *testing.T) {
	a, r, _ := newRadioRestartApp(t, func(string) (bool, error) { return true, nil })
	before := append([]wifi.Profile(nil), r.profiles...)
	if _, err := a.SetIoTBroadcast(context.Background(), false, true); err != nil {
		t.Fatal(err)
	}
	for i, p := range r.profiles {
		if p.Index == 3 || p.Index == 7 {
			continue
		}
		if p.WLEnable != before[i].WLEnable || p.SSID != before[i].SSID {
			t.Fatalf("profile %d changed", p.Index)
		}
	}
}
