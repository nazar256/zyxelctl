package wifi

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	profile24GHz = 3
	profile5GHz  = 7
)

// Profile contains the stable WLAN fields used by guarded updates. Extra keeps
// the complete source object available for snapshots and later extensions.
type Profile struct {
	Index            int            `json:"Index"`
	Band             string         `json:"band,omitempty"`
	WLEnable         bool           `json:"wlEnable"`
	OneSSIDEnable    bool           `json:"oneSsidEnable"`
	SSID             string         `json:"SSID"`
	WLHide           bool           `json:"wlHide"`
	SecurityMode     string         `json:"SecurityMode"`
	Encryption       string         `json:"encryp"`
	AutoGenPSK       bool           `json:"AutoGenPSK"`
	PskDisplay       string         `json:"PskDisplay,omitempty"`
	RekeyingInterval int            `json:"RekeyingInterval"`
	IsolationEnable  bool           `json:"IsolationEnable"`
	BSSIDIsolation   bool           `json:"X_ZYXEL_BssIdIsolation"`
	Extra            map[string]any `json:"Extra,omitempty"`
}

func (p *Profile) UnmarshalJSON(data []byte) error {
	type profileAlias Profile
	var decoded profileAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	delete(raw, "Extra")
	*p = Profile(decoded)
	p.Extra = raw
	return nil
}

func (p Profile) MarshalJSON() ([]byte, error) {
	raw := make(map[string]any, len(p.Extra)+14)
	for key, value := range p.Extra {
		raw[key] = value
	}
	raw["Index"] = p.Index
	if p.Band != "" {
		raw["band"] = p.Band
	}
	raw["wlEnable"] = p.WLEnable
	raw["oneSsidEnable"] = p.OneSSIDEnable
	raw["SSID"] = p.SSID
	raw["wlHide"] = p.WLHide
	raw["SecurityMode"] = p.SecurityMode
	raw["encryp"] = p.Encryption
	raw["AutoGenPSK"] = p.AutoGenPSK
	if p.PskDisplay != "" {
		raw["PskDisplay"] = p.PskDisplay
	}
	raw["RekeyingInterval"] = p.RekeyingInterval
	raw["IsolationEnable"] = p.IsolationEnable
	raw["X_ZYXEL_BssIdIsolation"] = p.BSSIDIsolation
	return json.Marshal(raw)
}

// IsHomeGuest mirrors the b29 frontend: exactly one isolation flag is true.
func IsHomeGuest(profile Profile) bool {
	return profile.IsolationEnable != profile.BSSIDIsolation
}

func ValidateSSID(ssid string) error {
	if len(ssid) == 0 || len(ssid) > 32 || !utf8.ValidString(ssid) {
		return errors.New("SSID must contain 1-32 valid UTF-8 bytes")
	}
	for _, r := range ssid {
		if unicode.IsControl(r) {
			return errors.New("SSID must not contain control characters")
		}
	}
	return nil
}

func ValidatePassphrase(passphrase string) error {
	if len(passphrase) < 8 || len(passphrase) > 63 {
		return errors.New("WPA2 passphrase must contain 8-63 printable ASCII characters")
	}
	for _, b := range []byte(passphrase) {
		if b < 0x20 || b > 0x7e {
			return errors.New("WPA2 passphrase must contain 8-63 printable ASCII characters")
		}
	}
	return nil
}

func ValidatePair(profiles []Profile) error {
	if len(profiles) != 2 {
		return errors.New("expected exactly WLAN profiles 3 and 7")
	}
	if profiles[0].Index != profile24GHz || profiles[1].Index != profile5GHz {
		return errors.New("expected WLAN profiles 3 and 7 in band order")
	}
	first, second := profiles[0], profiles[1]
	if !first.WLEnable || !second.WLEnable {
		return errors.New("both IoT WLAN profiles must already be enabled")
	}
	if !first.OneSSIDEnable || !second.OneSSIDEnable {
		return errors.New("both IoT WLAN profiles must use one-SSID mode")
	}
	if first.SSID != second.SSID {
		return errors.New("IoT WLAN profiles have different SSIDs")
	}
	if first.SecurityMode != second.SecurityMode {
		return errors.New("IoT WLAN profiles have different security modes")
	}
	if first.SecurityMode != "WPA2-Personal" {
		return fmt.Errorf("unsupported IoT WLAN security mode %q", first.SecurityMode)
	}
	if !IsHomeGuest(first) || !IsHomeGuest(second) {
		return errors.New("both IoT WLAN profiles must already be Home Guest profiles")
	}
	if first.IsolationEnable != second.IsolationEnable || first.BSSIDIsolation != second.BSSIDIsolation {
		return errors.New("IoT WLAN profiles have different isolation flags")
	}
	return nil
}

func BuildUpdatePayload(before []Profile, ssid, passphrase string) ([]map[string]any, error) {
	if err := ValidatePair(before); err != nil {
		return nil, err
	}
	if err := ValidateSSID(ssid); err != nil {
		return nil, err
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, err
	}
	payload := make([]map[string]any, 0, len(before))
	for _, profile := range before {
		payload = append(payload, map[string]any{
			"Index":                  profile.Index,
			"wlEnable":               profile.WLEnable,
			"oneSsidEnable":          profile.OneSSIDEnable,
			"SSID":                   ssid,
			"wlHide":                 profile.WLHide,
			"securityLevel":          "MoreSecure",
			"wpaMode":                "wpa2psk",
			"encryp":                 profile.Encryption,
			"AutoGenPSK":             profile.AutoGenPSK,
			"psk_value":              passphrase,
			"RekeyingInterval":       profile.RekeyingInterval,
			"wlEnableGuest":          true,
			"wlGwMode":               1,
			"IsolationEnable":        profile.IsolationEnable,
			"X_ZYXEL_BssIdIsolation": profile.BSSIDIsolation,
		})
	}
	return payload, nil
}

// BuildPeerAccessPayload keeps the WLAN a Home Guest network while moving
// from the observed client-isolating flag orientation to the alternate
// orientation that is exercised by the peer-access trial.
func BuildPeerAccessPayload(before []Profile) ([]map[string]any, error) {
	if err := ValidatePair(before); err != nil {
		return nil, err
	}
	if before[0].IsolationEnable || !before[0].BSSIDIsolation {
		return nil, errors.New("IoT WLAN is not in the expected client-isolating Home Guest orientation")
	}
	if before[0].PskDisplay == "" || before[0].PskDisplay != before[1].PskDisplay {
		return nil, errors.New("IoT WLAN profiles have missing or inconsistent WPA2 passphrases")
	}
	updated := append([]Profile(nil), before...)
	for i := range updated {
		updated[i].IsolationEnable = true
		updated[i].BSSIDIsolation = false
	}
	payload, err := BuildUpdatePayload(updated, updated[0].SSID, updated[0].PskDisplay)
	if err != nil {
		return nil, err
	}
	for _, profile := range payload {
		profile["div_wifiSubnet"] = true
		profile["wlSubnetState"] = false
		profile["subnetObjAction"] = nil
		profile["MinAddress"] = nil
		profile["MaxAddress"] = nil
		profile["SubnetMask"] = nil
		profile["LANIP"] = nil
		profile["Interface"] = nil
	}
	return payload, nil
}

// BuildIsolationProbePayload tests whether the backend accepts a narrow
// isolation-field update without the UI's guest-mode fields overriding it.
func BuildIsolationProbePayload(before []Profile) ([]map[string]any, error) {
	if err := ValidatePair(before); err != nil {
		return nil, err
	}
	if before[0].IsolationEnable || !before[0].BSSIDIsolation {
		return nil, errors.New("IoT WLAN is not in the expected Home Guest orientation")
	}
	return []map[string]any{
		{"Index": before[0].Index, "IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false},
		{"Index": before[1].Index, "IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false},
	}, nil
}
