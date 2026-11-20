package app

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nazar256/zyxelctl/internal/router"
)

type subnetRouter struct {
	*bandSyncRouter
	ignoreSubnet  bool
	inactiveBSSID bool
}

func (r *subnetRouter) Put(ctx context.Context, path string, payload any) error {
	err := r.writeRouter.Put(ctx, path, payload)
	p, ok := payload.(map[string]any)
	if !ok {
		return fmt.Errorf("expected single guest editor object")
	}
	index := p["Index"].(int)
	if index != 3 && index != 7 {
		return fmt.Errorf("non-IoT write")
	}
	for i := range r.profiles {
		if r.profiles[i].Index != index {
			continue
		}
		if index == 7 {
			if len(p) != 2 {
				return fmt.Errorf("5 GHz enable-only change must not resend credentials")
			}
			r.profiles[i].WLEnable = p["wlEnable"].(bool)
			if r.inactiveBSSID {
				r.profiles[i].Extra["BSSID"] = ""
				if r.profiles[i].WLEnable {
					r.profiles[i].Extra["BSSID"] = "02:00:5e:50:00:01"
				}
			}
			return err
		}
		if p["secMode"] != 255 {
			return fmt.Errorf("Guest editor MoreSecure code is 255")
		}
		if p["SSID"] != "IoT-Lab" || p["psk_value"] != "new-password" || p["wlEnableGuest"] != true || p["wlGwMode"] != 1 {
			return fmt.Errorf("guest settings not preserved")
		}
		r.profiles[i].WLEnable = p["wlEnable"].(bool)
		if index == 3 && !r.ignoreSubnet {
			if p["wlSubnetState"] == true {
				for _, key := range []string{"wlSubnetState", "MinAddress", "MaxAddress", "SubnetMask", "LANIP", "Interface"} {
					r.profiles[i].Extra[key] = p[key]
				}
			} else if p["subnetObjAction"] == "DELETE" {
				for _, key := range []string{"wlSubnetState", "MinAddress", "MaxAddress", "SubnetMask", "LANIP", "Interface"} {
					delete(r.profiles[i].Extra, key)
				}
			}
		}
	}
	return err
}

func TestIoTSubnetGuestEditorPayloadUsesFirmwareSecurityCode(t *testing.T) {
	_, r, _ := newSubnetApp(t)
	for _, p := range r.profiles {
		if p.Index == 3 {
			payload := buildIoTSubnetPayload(p, true, &iotSubnetConfig{Gateway: "10.99.0.1", Start: "10.99.0.2", End: "10.99.0.100", Mask: "255.255.255.0"}, "POST")
			if payload["secMode"] != 255 {
				t.Fatalf("wrong security enum: %v", payload["secMode"])
			}
		}
	}
}

func newSubnetApp(t *testing.T) (*App, *subnetRouter, *backupStore) {
	a, b, s := newBandSyncApp(t)
	for i := range b.profiles {
		b.profiles[i].OneSSIDEnable = false
		b.profiles[i].Extra["oneSsidEnable_ori"] = false
	}
	b.steering = false
	r := &subnetRouter{bandSyncRouter: b}
	a.router = r
	return a, r, s
}

func TestIoTSubnetCreateNoopAndDisable(t *testing.T) {
	a, r, s := newSubnetApp(t)
	result, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true)
	if err != nil || !result.Changed || r.putCalls != 2 {
		t.Fatalf("create %#v %v puts=%d", result, err, r.putCalls)
	}
	if len(s.files["iot-subnet.json"]) == 0 {
		t.Fatal("missing rollback metadata")
	}
	result, err = a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true)
	if err != nil || result.Changed || r.putCalls != 2 {
		t.Fatalf("noop %#v %v", result, err)
	}
	result, err = a.ConfigureIoTSubnet(context.Background(), "", "", "", true, true)
	if err != nil || !result.Changed || r.putCalls != 3 {
		t.Fatalf("disable %#v %v puts=%d", result, err, r.putCalls)
	}
}

func TestIoTSubnetRefusesUnsafeSettings(t *testing.T) {
	for _, tc := range []struct{ gateway, start, end string }{
		{"192.168.1.1/24", "192.168.1.2", "192.168.1.100"},
		{"8.8.8.1/24", "8.8.8.2", "8.8.8.100"},
		{"10.99.0.0/24", "10.99.0.2", "10.99.0.100"},
		{"10.99.0.1/24", "10.99.0.1", "10.99.0.100"},
		{"10.99.0.1/24", "10.99.0.100", "10.99.0.2"},
		{"10.99.0.1/24", "10.99.0.2", "192.168.21.100"},
	} {
		a, r, _ := newSubnetApp(t)
		if _, err := a.ConfigureIoTSubnet(context.Background(), tc.gateway, tc.start, tc.end, false, true); err == nil || r.putCalls != 0 {
			t.Fatalf("unsafe range accepted: %+v err=%v", tc, err)
		}
	}
	for _, kind := range []string{"sync enabled", "wrong SSID", "isolation", "backup"} {
		a, r, s := newSubnetApp(t)
		switch kind {
		case "sync enabled":
			for i := range r.profiles {
				r.profiles[i].OneSSIDEnable = true
			}
		case "wrong SSID":
			r.profiles[1].SSID = "Other"
		case "isolation":
			r.profiles[1].BSSIDIsolation = false
		case "backup":
			s.failFile = "iot-subnet.json"
		}
		if _, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true); err == nil || r.putCalls != 0 {
			t.Fatalf("unsafe preflight %s: %v", kind, err)
		}
	}
}

func TestIoTSubnetIgnoredRequestRestoresFiveGHz(t *testing.T) {
	a, r, _ := newSubnetApp(t)
	r.ignoreSubnet = true
	result, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true)
	if err == nil || !result.RollbackVerified {
		t.Fatalf("ignored subnet accepted: %#v %v", result, err)
	}
	for _, p := range r.profiles {
		if (p.Index == 3 || p.Index == 7) && !p.WLEnable {
			t.Fatal("original IoT enable not restored")
		}
	}
}

func TestIoTSubnetUncertainCreateIsNotReplayed(t *testing.T) {
	a, r, _ := newSubnetApp(t)
	r.retryAuth = true
	r.putErrors = map[int]error{2: router.ErrUnauthenticated}
	result, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true)
	if err == nil || !result.RollbackVerified {
		t.Fatalf("uncertain result %#v %v", result, err)
	}
	posts := 0
	for _, value := range r.putPayloads {
		if value.(map[string]any)["subnetObjAction"] == "POST" {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("uncertain POST replayed %d times", posts)
	}
}

func TestIoTSubnetAlreadyCorrectOnlyDisablesFiveGHz(t *testing.T) {
	a, r, _ := newSubnetApp(t)
	if _, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true); err != nil {
		t.Fatal(err)
	}
	for i := range r.profiles {
		if r.profiles[i].Index == 7 {
			r.profiles[i].WLEnable = true
		}
	}
	count := r.putCalls
	if _, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true); err != nil {
		t.Fatal(err)
	}
	if r.putCalls != count+1 || r.putPayloads[count].(map[string]any)["Index"] != 7 {
		t.Fatalf("unnecessary subnet update: %v", r.putPayloads[count:])
	}
}

func TestIoTSubnetConfirmationDescribesActualAction(t *testing.T) {
	a, _, _ := newSubnetApp(t)
	var prompt string
	a.output.Confirm = func(message string) (bool, error) { prompt = message; return true, nil }
	if _, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "disable IoT 5 GHz") {
		t.Fatalf("create prompt: %s", prompt)
	}
	if _, err := a.ConfigureIoTSubnet(context.Background(), "", "", "", true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "retain") || strings.Contains(prompt, "disable IoT 5 GHz") {
		t.Fatalf("remove prompt: %s", prompt)
	}
}

func TestIoTSubnetAcceptsInactiveBSSIDOnlyOnDisabledTarget(t *testing.T) {
	a, r, _ := newSubnetApp(t)
	r.inactiveBSSID = true
	for i := range r.profiles {
		if r.profiles[i].Index == 7 {
			r.profiles[i].Extra["BSSID"] = "02:00:5e:50:00:01"
		}
	}
	result, err := a.ConfigureIoTSubnet(context.Background(), "10.99.0.1/24", "10.99.0.2", "10.99.0.100", false, true)
	if err != nil || !result.Changed {
		t.Fatalf("disabled BSSID treated as configuration: %#v %v", result, err)
	}
}

func TestIoTSubnetStillRejectsEnabledAndOtherBSSIDChanges(t *testing.T) {
	for _, index := range []int{1, 7} {
		_, r, _ := newSubnetApp(t)
		before, err := readBandSyncState(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		for i := range r.profiles {
			if r.profiles[i].Index == index {
				r.profiles[i].Extra["BSSID"] = "unexpected identity"
			}
		}
		after, err := readBandSyncState(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyIoTSubnet(before, after, nil, true); err == nil {
			t.Fatalf("BSSID change accepted for enabled profile %d", index)
		}
	}
}
