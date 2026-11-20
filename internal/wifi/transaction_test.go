package wifi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func transactionProfiles() []Profile {
	profiles := []Profile{
		{Index: 1, WLEnable: true, SSID: "Primary", SecurityMode: "WPA2-Personal", Encryption: "aes", RekeyingInterval: 3600},
		validPair()[0],
		{Index: 5, WLEnable: true, SSID: "Primary-5", SecurityMode: "WPA2-Personal", Encryption: "aes", RekeyingInterval: 3600},
		validPair()[1],
	}
	return profiles
}

func changedProfiles() []Profile {
	profiles := transactionProfiles()
	for i := range profiles {
		if profiles[i].Index == 3 || profiles[i].Index == 7 {
			profiles[i].SSID = "IoT-Lab"
			profiles[i].PskDisplay = "new-password"
		}
	}
	return profiles
}

func peerAccessibleProfiles() []Profile {
	profiles := transactionProfiles()
	for i := range profiles {
		if profiles[i].Index == 3 || profiles[i].Index == 7 {
			profiles[i].IsolationEnable = true
			profiles[i].BSSIDIsolation = false
		}
	}
	return profiles
}

func TestVerifyChangeAcceptsOnlyRequestedTargetChanges(t *testing.T) {
	if err := VerifyChange(transactionProfiles(), changedProfiles(), "IoT-Lab", "new-password", true, true); err != nil {
		t.Fatalf("VerifyChange() error = %v", err)
	}
}

func TestVerifyChangeRejectsTargetAndInfrastructureDrift(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func([]Profile)
		dhcpBefore bool
		dhcpAfter  bool
	}{
		{"wrong SSID", func(p []Profile) { p[1].SSID = "wrong" }, true, true},
		{"wrong password", func(p []Profile) { p[1].PskDisplay = "wrong-password" }, true, true},
		{"disabled target", func(p []Profile) { p[1].WLEnable = false }, true, true},
		{"one SSID changed", func(p []Profile) { p[1].OneSSIDEnable = false }, true, true},
		{"isolation changed", func(p []Profile) { p[1].BSSIDIsolation = false }, true, true},
		{"security changed", func(p []Profile) { p[1].SecurityMode = "WPA3-Personal" }, true, true},
		{"non-target changed", func(p []Profile) { p[0].SSID = "Changed-Primary" }, true, true},
		{"DHCP changed", func([]Profile) {}, true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			after := changedProfiles()
			test.mutate(after)
			if err := VerifyChange(transactionProfiles(), after, "IoT-Lab", "new-password", test.dhcpBefore, test.dhcpAfter); err == nil {
				t.Fatal("VerifyChange() error = nil")
			}
		})
	}
}

func TestVerifyPeerAccessChangeAcceptsOnlyIsolationOrientationSwap(t *testing.T) {
	if err := VerifyPeerAccessChange(transactionProfiles(), peerAccessibleProfiles(), true, true); err != nil {
		t.Fatalf("VerifyPeerAccessChange() error = %v", err)
	}
}

func TestVerifyPeerAccessChangeRejectsTargetAndInfrastructureDrift(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func([]Profile)
		dhcpBefore bool
		dhcpAfter  bool
	}{
		{"wrong orientation", func(p []Profile) { p[1].IsolationEnable = false; p[1].BSSIDIsolation = true }, true, true},
		{"SSID changed", func(p []Profile) { p[1].SSID = "Changed" }, true, true},
		{"password changed", func(p []Profile) { p[1].PskDisplay = "changed-password" }, true, true},
		{"target disabled", func(p []Profile) { p[1].WLEnable = false }, true, true},
		{"non-target changed", func(p []Profile) { p[0].SSID = "Changed-Primary" }, true, true},
		{"DHCP changed", func([]Profile) {}, true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			after := peerAccessibleProfiles()
			test.mutate(after)
			if err := VerifyPeerAccessChange(transactionProfiles(), after, test.dhcpBefore, test.dhcpAfter); err == nil {
				t.Fatal("VerifyPeerAccessChange() error = nil")
			}
		})
	}
}

func TestVerifyPeerAccessChangeNamesMismatchedFieldsWithoutSecrets(t *testing.T) {
	after := peerAccessibleProfiles()
	after[1].IsolationEnable = false
	after[1].BSSIDIsolation = true
	after[1].PskDisplay = "new-secret-that-must-not-leak"
	err := VerifyPeerAccessChange(transactionProfiles(), after, true, true)
	if err == nil {
		t.Fatal("expected a mismatch")
	}
	message := err.Error()
	for _, field := range []string{"IsolationEnable", "X_ZYXEL_BssIdIsolation", "PskDisplay"} {
		if !strings.Contains(message, field) {
			t.Fatalf("missing field %q in %q", field, message)
		}
	}
	if strings.Contains(message, "new-secret-that-must-not-leak") || strings.Contains(message, "old-password") {
		t.Fatalf("mismatch exposed a passphrase: %q", message)
	}
}

func TestBuildRestorePayloadReconstructsProfilesThreeAndSeven(t *testing.T) {
	got, err := BuildRestorePayload(validPair())
	if err != nil {
		t.Fatal(err)
	}
	want, err := BuildUpdatePayload(validPair(), "IoT-LAB", "old-password")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildRestorePayload() = %#v, want %#v", got, want)
	}
}

func TestBuildRestorePayloadRejectsMalformedSnapshot(t *testing.T) {
	for _, profiles := range [][]Profile{
		nil,
		validPair()[:1],
		{{Index: 3}, {Index: 8}},
		func() []Profile { p := validPair(); p[0].PskDisplay = ""; return p }(),
	} {
		if _, err := BuildRestorePayload(profiles); err == nil {
			t.Fatalf("BuildRestorePayload(%#v) error = nil", profiles)
		}
	}
}

func TestProfileJSONSnapshotPreservesUnknownRouterFields(t *testing.T) {
	raw := []byte(`{"Index":3,"wlEnable":true,"oneSsidEnable":true,"SSID":"IoT-LAB","SecurityMode":"WPA2-Personal","encryp":"aes","PskDisplay":"old-password","RekeyingInterval":3600,"IsolationEnable":false,"X_ZYXEL_BssIdIsolation":true,"FirmwareOnlyField":"preserved"}`)
	var profile Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"FirmwareOnlyField":"preserved"`) {
		t.Fatalf("snapshot lost unknown field: %s", encoded)
	}
}
