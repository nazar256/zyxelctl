package wifi

import (
	"encoding/json"
	"testing"
)

func extenderIoTFixture(t *testing.T) []Profile {
	t.Helper()
	var profiles []Profile
	if err := json.Unmarshal([]byte(`[
		{"Index":1,"SSID":"Trusted-Net","wlEnable":true,"MainSSID":true,"IsolationEnable":false,"X_ZYXEL_BssIdIsolation":false},
		{"Index":3,"SSID":"IoT-Lab","band":"2.4GHz","wlEnable":true,"oneSsidEnable":true,"SecurityMode":"WPA2-Personal","MainSSID":false,"IsolationEnable":true,"X_ZYXEL_BssIdIsolation":true,"upRate":0},
		{"Index":7,"SSID":"IoT-Lab","band":"5GHz","wlEnable":true,"oneSsidEnable":true,"SecurityMode":"WPA2-Personal","MainSSID":false,"IsolationEnable":true,"X_ZYXEL_BssIdIsolation":true,"upRate":0}
	]`), &profiles); err != nil {
		t.Fatal(err)
	}
	return profiles
}

func TestExtenderIoTModesRefusesUnexpectedTargets(t *testing.T) {
	for _, mutate := range []func([]Profile){
		func(p []Profile) { p[1].SSID = "GuestNet" },
		func(p []Profile) { p[2].Index = 6 },
		func(p []Profile) { p[2].Band = "2.4GHz" },
		func(p []Profile) { p[1].Extra["MainSSID"] = true },
		func(p []Profile) { delete(p[1].Extra, "MainSSID") },
		func(p []Profile) { p[1].WLEnable = false },
		func(p []Profile) { p[1].OneSSIDEnable = false },
		func(p []Profile) { p[1].SecurityMode = "None" },
		func(p []Profile) { p[1].BSSIDIsolation = false },
	} {
		profiles := extenderIoTFixture(t)
		mutate(profiles)
		if _, err := ExtenderIoTModes(profiles); err == nil {
			t.Fatal("unsafe IoT target accepted")
		}
	}
	profiles := extenderIoTFixture(t)
	modes, err := ExtenderIoTModes(profiles)
	if err != nil || modes[3] != 0 || modes[7] != 0 || len(modes) != 2 {
		t.Fatalf("external guest modes: %v, %v", modes, err)
	}
	profiles[1].IsolationEnable = false
	modes, err = ExtenderIoTModes(profiles)
	if err != nil || modes[3] != 1 || modes[7] != 0 {
		t.Fatalf("mixed modes: %v, %v", modes, err)
	}
}

func TestVerifyExtenderIoTModesPreservesAllOtherSettings(t *testing.T) {
	before := extenderIoTFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func([]Profile)
		wantOK bool
	}{
		{"only requested flags", func(p []Profile) {}, true},
		{"normalization", func(p []Profile) { p[2].IsolationEnable = true }, false},
		{"other SSID", func(p []Profile) { p[0].SSID = "changed" }, false},
		{"other isolation", func(p []Profile) { p[0].IsolationEnable = true }, false},
		{"unknown configuration", func(p []Profile) { p[1].Extra["upRate"] = float64(10) }, false},
		{"missing profile", func(p []Profile) { p[0].Index = 9 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := extenderIoTFixture(t)
			after[1].IsolationEnable, after[2].IsolationEnable = false, false
			tc.mutate(after)
			err := VerifyExtenderIoTModes(before, after, map[int]int{3: 1, 7: 1})
			if (err == nil) != tc.wantOK {
				t.Fatalf("verify error=%v, wantOK=%t", err, tc.wantOK)
			}
		})
	}
}
