package wifi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ExtenderIoTModes accepts only the existing IoT pair on the known extender.
// The firmware UI selects External Guest with mode 0 and Home Guest with mode 1.
func ExtenderIoTModes(profiles []Profile) (map[int]int, error) {
	byIndex, err := indexProfiles(profiles)
	if err != nil {
		return nil, err
	}
	ssid, err := GuestPairSSID(profiles)
	if err != nil {
		return nil, err
	}
	modes := make(map[int]int, 2)
	for _, target := range []struct {
		index int
		band  string
	}{{3, "2.4GHz"}, {7, "5GHz"}} {
		profile, ok := byIndex[target.index]
		mainSSID, hasMainSSID := profile.Extra["MainSSID"].(bool)
		if !ok || profile.SSID != ssid || profile.Band != target.band || !profile.WLEnable || !profile.OneSSIDEnable || profile.SecurityMode != "WPA2-Personal" || !hasMainSSID || mainSSID || !profile.BSSIDIsolation {
			return nil, errors.New("expected enabled WPA2 guest profiles 3 and 7 with network isolation retained")
		}
		if profile.IsolationEnable {
			modes[target.index] = 0
		} else {
			modes[target.index] = 1
		}
	}
	return modes, nil
}

// VerifyExtenderIoTModes compares the complete WLAN objects, including fields
// unknown to Profile, while allowing only the requested IoT guest-mode flags.
func VerifyExtenderIoTModes(before, after []Profile, modes map[int]int) error {
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
	for index, expected := range beforeByIndex {
		current, ok := afterByIndex[index]
		if !ok {
			return fmt.Errorf("WLAN profile %d disappeared", index)
		}
		if mode, target := modes[index]; target {
			if (index != 3 && index != 7) || (mode != 0 && mode != 1) {
				return errors.New("invalid IoT guest-mode verification target")
			}
			expected.IsolationEnable, expected.BSSIDIsolation = mode == 0, true
		}
		want, err := json.Marshal(expected)
		if err != nil {
			return errors.New("encode expected WLAN state")
		}
		got, err := json.Marshal(current)
		if err != nil {
			return errors.New("encode current WLAN state")
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("WLAN profile %d changed outside the requested guest mode or did not retain it", index)
		}
	}
	return nil
}
