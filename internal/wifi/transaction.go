package wifi

import (
	"errors"
	"fmt"
	"strings"
)

func BuildRestorePayload(snapshot []Profile) ([]map[string]any, error) {
	if err := ValidatePair(snapshot); err != nil {
		return nil, fmt.Errorf("invalid WLAN snapshot: %w", err)
	}
	if snapshot[0].PskDisplay == "" || snapshot[1].PskDisplay == "" || snapshot[0].PskDisplay != snapshot[1].PskDisplay {
		return nil, errors.New("invalid WLAN snapshot: missing or inconsistent WPA2 passphrase")
	}
	return BuildUpdatePayload(snapshot, snapshot[0].SSID, snapshot[0].PskDisplay)
}

func VerifyChange(before, after []Profile, expectedSSID, expectedPassphrase string, dhcpBefore, dhcpAfter bool) error {
	if dhcpBefore != dhcpAfter {
		return errors.New("DHCP enabled state changed")
	}
	beforeByIndex, err := indexProfiles(before)
	if err != nil {
		return err
	}
	afterByIndex, err := indexProfiles(after)
	if err != nil {
		return err
	}
	if len(beforeByIndex) != len(afterByIndex) {
		return errors.New("WLAN profile count changed")
	}
	for index, original := range beforeByIndex {
		current, ok := afterByIndex[index]
		if !ok {
			return fmt.Errorf("WLAN profile %d disappeared", index)
		}
		if index == profile24GHz || index == profile5GHz {
			if current.SSID != expectedSSID {
				return fmt.Errorf("IoT WLAN profile %d has an unexpected SSID", index)
			}
			if current.PskDisplay != expectedPassphrase {
				return fmt.Errorf("IoT WLAN profile %d did not retain the requested passphrase", index)
			}
			if !targetOperationalEqual(original, current) {
				return fmt.Errorf("IoT WLAN profile %d changed outside SSID/passphrase", index)
			}
			continue
		}
		if !criticalEqual(original, current) {
			return fmt.Errorf("non-target WLAN profile %d changed", index)
		}
	}
	targets := []Profile{afterByIndex[profile24GHz], afterByIndex[profile5GHz]}
	if err := ValidatePair(targets); err != nil {
		return fmt.Errorf("updated IoT WLAN is invalid: %w", err)
	}
	return nil
}

func VerifyPeerAccessChange(before, after []Profile, dhcpBefore, dhcpAfter bool) error {
	if dhcpBefore != dhcpAfter {
		return errors.New("DHCP enabled state changed")
	}
	beforeByIndex, err := indexProfiles(before)
	if err != nil {
		return err
	}
	afterByIndex, err := indexProfiles(after)
	if err != nil {
		return err
	}
	if len(beforeByIndex) != len(afterByIndex) {
		return errors.New("WLAN profile count changed")
	}
	for index, original := range beforeByIndex {
		current, ok := afterByIndex[index]
		if !ok {
			return fmt.Errorf("WLAN profile %d disappeared", index)
		}
		if index == profile24GHz || index == profile5GHz {
			expected := original
			expected.IsolationEnable = true
			expected.BSSIDIsolation = false
			if !criticalEqual(expected, current) {
				return fmt.Errorf("IoT WLAN profile %d differed in: %s", index, strings.Join(criticalDiffFields(expected, current), ", "))
			}
			continue
		}
		if !criticalEqual(original, current) {
			return fmt.Errorf("non-target WLAN profile %d changed", index)
		}
	}
	targets := []Profile{afterByIndex[profile24GHz], afterByIndex[profile5GHz]}
	if err := ValidatePair(targets); err != nil {
		return fmt.Errorf("updated IoT WLAN is invalid: %w", err)
	}
	return nil
}

// criticalDiffFields names changed settings without disclosing their values.
// In particular, neither a Wi-Fi passphrase nor an SSID enters an error.
func criticalDiffFields(expected, current Profile) []string {
	var fields []string
	if expected.Index != current.Index {
		fields = append(fields, "Index")
	}
	if expected.WLEnable != current.WLEnable {
		fields = append(fields, "wlEnable")
	}
	if expected.OneSSIDEnable != current.OneSSIDEnable {
		fields = append(fields, "oneSsidEnable")
	}
	if expected.WLHide != current.WLHide {
		fields = append(fields, "wlHide")
	}
	if expected.SecurityMode != current.SecurityMode {
		fields = append(fields, "SecurityMode")
	}
	if expected.Encryption != current.Encryption {
		fields = append(fields, "encryp")
	}
	if expected.AutoGenPSK != current.AutoGenPSK {
		fields = append(fields, "AutoGenPSK")
	}
	if expected.RekeyingInterval != current.RekeyingInterval {
		fields = append(fields, "RekeyingInterval")
	}
	if expected.IsolationEnable != current.IsolationEnable {
		fields = append(fields, "IsolationEnable")
	}
	if expected.BSSIDIsolation != current.BSSIDIsolation {
		fields = append(fields, "X_ZYXEL_BssIdIsolation")
	}
	if expected.SSID != current.SSID {
		fields = append(fields, "SSID")
	}
	if expected.PskDisplay != current.PskDisplay {
		fields = append(fields, "PskDisplay")
	}
	return fields
}

func VerifyRestore(snapshot, current []Profile) error {
	if len(snapshot) != 2 {
		return errors.New("restore snapshot must contain profiles 3 and 7")
	}
	currentByIndex, err := indexProfiles(current)
	if err != nil {
		return err
	}
	for _, expected := range snapshot {
		actual, ok := currentByIndex[expected.Index]
		if !ok || !criticalEqual(expected, actual) || expected.PskDisplay != actual.PskDisplay {
			return fmt.Errorf("restored WLAN profile %d does not match snapshot", expected.Index)
		}
	}
	return nil
}

func indexProfiles(profiles []Profile) (map[int]Profile, error) {
	result := make(map[int]Profile, len(profiles))
	for _, profile := range profiles {
		if _, exists := result[profile.Index]; exists {
			return nil, fmt.Errorf("duplicate WLAN profile index %d", profile.Index)
		}
		result[profile.Index] = profile
	}
	return result, nil
}

func targetOperationalEqual(before, after Profile) bool {
	return before.Index == after.Index &&
		before.WLEnable == after.WLEnable &&
		before.OneSSIDEnable == after.OneSSIDEnable &&
		before.WLHide == after.WLHide &&
		before.SecurityMode == after.SecurityMode &&
		before.Encryption == after.Encryption &&
		before.AutoGenPSK == after.AutoGenPSK &&
		before.RekeyingInterval == after.RekeyingInterval &&
		before.IsolationEnable == after.IsolationEnable &&
		before.BSSIDIsolation == after.BSSIDIsolation
}

func criticalEqual(before, after Profile) bool {
	return targetOperationalEqual(before, after) &&
		before.SSID == after.SSID &&
		before.PskDisplay == after.PskDisplay
}
