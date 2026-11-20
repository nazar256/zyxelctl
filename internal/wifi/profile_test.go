package wifi

import (
	"reflect"
	"strings"
	"testing"
)

func validPair() []Profile {
	return []Profile{
		{
			Index: 3, Band: "2.4GHz", WLEnable: true, OneSSIDEnable: true,
			SSID: "IoT-LAB", WLHide: false, SecurityMode: "WPA2-Personal",
			Encryption: "aes", AutoGenPSK: false, PskDisplay: "old-password",
			RekeyingInterval: 3600, IsolationEnable: false, BSSIDIsolation: true,
			Extra: map[string]any{"MainSSID": false},
		},
		{
			Index: 7, Band: "5GHz", WLEnable: true, OneSSIDEnable: true,
			SSID: "IoT-LAB", WLHide: false, SecurityMode: "WPA2-Personal",
			Encryption: "aes", AutoGenPSK: false, PskDisplay: "old-password",
			RekeyingInterval: 3600, IsolationEnable: false, BSSIDIsolation: true,
			Extra: map[string]any{"MainSSID": false},
		},
	}
}

func TestIsHomeGuestTruthTable(t *testing.T) {
	tests := []struct {
		isolation bool
		bss       bool
		want      bool
	}{
		{false, false, false},
		{false, true, true},
		{true, false, true},
		{true, true, false},
	}
	for _, tt := range tests {
		profile := Profile{IsolationEnable: tt.isolation, BSSIDIsolation: tt.bss}
		if got := IsHomeGuest(profile); got != tt.want {
			t.Fatalf("IsHomeGuest(%t, %t) = %t, want %t", tt.isolation, tt.bss, got, tt.want)
		}
	}
}

func TestValidateSSIDBoundaries(t *testing.T) {
	valid := []string{"a", strings.Repeat("a", 32), "IoT-Lab", "Café"}
	for _, ssid := range valid {
		if err := ValidateSSID(ssid); err != nil {
			t.Errorf("ValidateSSID(%q) error = %v", ssid, err)
		}
	}
	invalid := []string{"", strings.Repeat("a", 33), strings.Repeat("é", 17), "bad\nname", "bad\x00name"}
	for _, ssid := range invalid {
		if err := ValidateSSID(ssid); err == nil {
			t.Errorf("ValidateSSID(%q) error = nil", ssid)
		}
	}
}

func TestValidatePassphraseBoundaries(t *testing.T) {
	valid := []string{strings.Repeat("a", 8), strings.Repeat("z", 63), "correct horse battery staple"}
	for _, passphrase := range valid {
		if err := ValidatePassphrase(passphrase); err != nil {
			t.Errorf("ValidatePassphrase(length %d) error = %v", len(passphrase), err)
		}
	}
	invalid := []string{strings.Repeat("a", 7), strings.Repeat("a", 64), "password\n", "pässword"}
	for _, passphrase := range invalid {
		if err := ValidatePassphrase(passphrase); err == nil {
			t.Errorf("ValidatePassphrase(%q) error = nil", passphrase)
		}
	}
}

func TestValidatePairAcceptsKnownHomeGuestPair(t *testing.T) {
	if err := ValidatePair(validPair()); err != nil {
		t.Fatalf("ValidatePair() error = %v", err)
	}
}

func TestValidatePairRejectsEveryRequiredDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]Profile) []Profile
	}{
		{"missing profile", func(p []Profile) []Profile { return p[:1] }},
		{"wrong indexes", func(p []Profile) []Profile { p[1].Index = 8; return p }},
		{"disabled", func(p []Profile) []Profile { p[0].WLEnable = false; return p }},
		{"different SSID", func(p []Profile) []Profile { p[1].SSID = "other"; return p }},
		{"different security", func(p []Profile) []Profile { p[1].SecurityMode = "WPA3-Personal"; return p }},
		{"unsupported common security", func(p []Profile) []Profile {
			p[0].SecurityMode = "WPA3-Personal"
			p[1].SecurityMode = "WPA3-Personal"
			return p
		}},
		{"one SSID off", func(p []Profile) []Profile { p[1].OneSSIDEnable = false; return p }},
		{"not Home Guest", func(p []Profile) []Profile { p[0].BSSIDIsolation = false; return p }},
		{"different isolation", func(p []Profile) []Profile { p[1].IsolationEnable = true; p[1].BSSIDIsolation = false; return p }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePair(tt.mutate(validPair())); err == nil {
				t.Fatal("ValidatePair() error = nil")
			}
		})
	}
}

func TestBuildUpdatePayloadPreservesOperationalFields(t *testing.T) {
	profiles := validPair()
	got, err := BuildUpdatePayload(profiles, "IoT-Lab", "new-password")
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{
			"Index": 3, "wlEnable": true, "oneSsidEnable": true,
			"SSID": "IoT-Lab", "wlHide": false,
			"securityLevel": "MoreSecure", "wpaMode": "wpa2psk", "encryp": "aes",
			"AutoGenPSK": false, "psk_value": "new-password", "RekeyingInterval": 3600,
			"wlEnableGuest": true, "wlGwMode": 1,
			"IsolationEnable": false, "X_ZYXEL_BssIdIsolation": true,
		},
		{
			"Index": 7, "wlEnable": true, "oneSsidEnable": true,
			"SSID": "IoT-Lab", "wlHide": false,
			"securityLevel": "MoreSecure", "wpaMode": "wpa2psk", "encryp": "aes",
			"AutoGenPSK": false, "psk_value": "new-password", "RekeyingInterval": 3600,
			"wlEnableGuest": true, "wlGwMode": 1,
			"IsolationEnable": false, "X_ZYXEL_BssIdIsolation": true,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildUpdatePayload() = %#v, want %#v", got, want)
	}
	if profiles[0].SSID != "IoT-LAB" || profiles[0].PskDisplay != "old-password" {
		t.Fatal("BuildUpdatePayload mutated input")
	}
}

func TestBuildPeerAccessPayloadSwapsOnlyIsolationOrientation(t *testing.T) {
	profiles := validPair()
	got, err := BuildPeerAccessPayload(profiles)
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{
			"Index": 3, "wlEnable": true, "oneSsidEnable": true,
			"SSID": "IoT-LAB", "wlHide": false,
			"securityLevel": "MoreSecure", "wpaMode": "wpa2psk", "encryp": "aes",
			"AutoGenPSK": false, "psk_value": "old-password", "RekeyingInterval": 3600,
			"wlEnableGuest": true, "wlGwMode": 1,
			"IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false,
			"div_wifiSubnet": true, "wlSubnetState": false, "subnetObjAction": nil,
			"MinAddress": nil, "MaxAddress": nil, "SubnetMask": nil, "LANIP": nil, "Interface": nil,
		},
		{
			"Index": 7, "wlEnable": true, "oneSsidEnable": true,
			"SSID": "IoT-LAB", "wlHide": false,
			"securityLevel": "MoreSecure", "wpaMode": "wpa2psk", "encryp": "aes",
			"AutoGenPSK": false, "psk_value": "old-password", "RekeyingInterval": 3600,
			"wlEnableGuest": true, "wlGwMode": 1,
			"IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false,
			"div_wifiSubnet": true, "wlSubnetState": false, "subnetObjAction": nil,
			"MinAddress": nil, "MaxAddress": nil, "SubnetMask": nil, "LANIP": nil, "Interface": nil,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildPeerAccessPayload() = %#v, want %#v", got, want)
	}
	if profiles[0].IsolationEnable || !profiles[0].BSSIDIsolation {
		t.Fatal("BuildPeerAccessPayload mutated input")
	}
}

func TestBuildPeerAccessPayloadRejectsUnexpectedOrientationOrPasswords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]Profile)
	}{
		{"already swapped", func(profiles []Profile) {
			for i := range profiles {
				profiles[i].IsolationEnable = true
				profiles[i].BSSIDIsolation = false
			}
		}},
		{"inconsistent passwords", func(profiles []Profile) { profiles[1].PskDisplay = "different-password" }},
		{"missing password", func(profiles []Profile) { profiles[0].PskDisplay = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profiles := validPair()
			test.mutate(profiles)
			if _, err := BuildPeerAccessPayload(profiles); err == nil {
				t.Fatal("BuildPeerAccessPayload() error = nil")
			}
		})
	}
}

func TestBuildIsolationProbePayloadTouchesOnlyTwoFlags(t *testing.T) {
	profiles := validPair()
	got, err := BuildIsolationProbePayload(profiles)
	if err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"Index": 3, "IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false},
		{"Index": 7, "IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildIsolationProbePayload() = %#v, want %#v", got, want)
	}
	if profiles[0].IsolationEnable || !profiles[0].BSSIDIsolation {
		t.Fatal("BuildIsolationProbePayload mutated input")
	}
}

func TestBuildIsolationProbePayloadRejectsUnexpectedOrientation(t *testing.T) {
	profiles := validPair()
	profiles[0].IsolationEnable = true
	profiles[0].BSSIDIsolation = false
	if _, err := BuildIsolationProbePayload(profiles); err == nil {
		t.Fatal("BuildIsolationProbePayload() error = nil")
	}
}
