package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/nazar256/zyxelctl/internal/wifi"
)

var iotSubnetFields = []string{"wlSubnetState", "MinAddress", "MaxAddress", "SubnetMask", "LANIP", "Interface"}

type iotSubnetConfig struct {
	Gateway string `json:"gateway"`
	Start   string `json:"dhcp_start"`
	End     string `json:"dhcp_end"`
	Mask    string `json:"subnet_mask"`
}

func parseIoTSubnet(gateway, start, end string, lan []map[string]any) (*iotSubnetConfig, error) {
	prefix, err := netip.ParsePrefix(gateway)
	first, e1 := netip.ParseAddr(start)
	last, e2 := netip.ParseAddr(end)
	if err != nil || e1 != nil || e2 != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < 16 || prefix.Bits() > 29 || !first.Is4() || !last.Is4() {
		return nil, errors.New("IoT subnet requires a private IPv4 gateway/prefix and DHCP start/end")
	}
	network := prefix.Masked()
	base := network.Addr().As4()
	broadcastBytes := base
	binary.BigEndian.PutUint32(broadcastBytes[:], binary.BigEndian.Uint32(base[:])|uint32((uint64(1)<<(32-prefix.Bits()))-1))
	broadcast := netip.AddrFrom4(broadcastBytes)
	if prefix.Addr() == network.Addr() || prefix.Addr() == broadcast || !network.Contains(first) || !network.Contains(last) || first == network.Addr() || last == broadcast || first.Compare(last) > 0 || (prefix.Addr().Compare(first) >= 0 && prefix.Addr().Compare(last) <= 0) {
		return nil, errors.New("invalid IoT gateway or DHCP range")
	}
	for _, record := range lan {
		ipText, _ := record["IPAddress"].(string)
		maskText, _ := record["SubnetMask"].(string)
		ip, err := netip.ParseAddr(ipText)
		mask := net.ParseIP(maskText).To4()
		if err != nil || mask == nil {
			return nil, errors.New("cannot verify existing LAN range")
		}
		ones, bits := net.IPMask(mask).Size()
		if bits != 32 {
			return nil, errors.New("invalid existing LAN mask")
		}
		existing := netip.PrefixFrom(ip, ones).Masked()
		if network.Overlaps(existing) {
			return nil, errors.New("IoT range overlaps the existing LAN")
		}
	}
	mask := net.IP(net.CIDRMask(prefix.Bits(), 32)).String()
	return &iotSubnetConfig{Gateway: prefix.Addr().String(), Start: first.String(), End: last.String(), Mask: mask}, nil
}

func iotSubnetTargets(state bandSyncState) (map[int]wifi.Profile, error) {
	if state.Profiles[0].OneSSIDEnable {
		return nil, errors.New("disable global band synchronization before configuring an IoT subnet")
	}
	ssid, err := wifi.GuestPairSSID(state.Profiles)
	if err != nil {
		return nil, err
	}
	targets := map[int]wifi.Profile{}
	for _, p := range state.Profiles {
		if p.Index != 3 && p.Index != 7 {
			continue
		}
		band := "2.4GHz"
		if p.Index == 7 {
			band = "5GHz"
		}
		if p.SSID != ssid || p.Band != band || p.Extra["MainSSID"] != false || p.SecurityMode != "WPA2-Personal" || p.IsolationEnable || !p.BSSIDIsolation || (p.Index == 3 && !p.WLEnable) {
			return nil, errors.New("expected original IoT Home Guest pair with 2.4 GHz enabled and network isolation retained")
		}
		if err := wifi.ValidatePassphrase(p.PskDisplay); p.Index == 3 && err != nil {
			return nil, errors.New("existing IoT passphrase is unavailable")
		}
		targets[p.Index] = p
	}
	if len(targets) != 2 {
		return nil, errors.New("missing IoT profiles 3 and 7")
	}
	return targets, nil
}

func currentIoTSubnet(p wifi.Profile) (*iotSubnetConfig, error) {
	if p.Extra["wlSubnetState"] == nil || p.Extra["wlSubnetState"] == false {
		for _, key := range []string{"MinAddress", "MaxAddress", "SubnetMask", "LANIP", "Interface"} {
			if value := p.Extra[key]; value != nil && value != "" {
				return nil, errors.New("inconsistent disabled IoT subnet fields")
			}
		}
		return nil, nil
	}
	if p.Extra["wlSubnetState"] != true {
		return nil, errors.New("unknown IoT subnet state")
	}
	config := &iotSubnetConfig{}
	for _, item := range []struct {
		key    string
		target *string
	}{{"LANIP", &config.Gateway}, {"MinAddress", &config.Start}, {"MaxAddress", &config.End}, {"SubnetMask", &config.Mask}} {
		value, ok := p.Extra[item.key].(string)
		if !ok || value == "" {
			return nil, errors.New("incomplete existing IoT subnet")
		}
		*item.target = value
	}
	if value := p.Extra["Interface"]; value != nil && value != "WiFi.SSID.3" {
		return nil, errors.New("unexpected IoT subnet interface")
	}
	return config, nil
}

func subnetValues(config *iotSubnetConfig) map[string]any {
	if config == nil {
		return map[string]any{"wlSubnetState": false, "MinAddress": nil, "MaxAddress": nil, "SubnetMask": nil, "LANIP": nil, "Interface": nil}
	}
	return map[string]any{"wlSubnetState": true, "MinAddress": config.Start, "MaxAddress": config.End, "SubnetMask": config.Mask, "LANIP": config.Gateway, "Interface": "WiFi.SSID.3"}
}

func buildIoTSubnetPayload(p wifi.Profile, enabled bool, config *iotSubnetConfig, action string) map[string]any {
	if p.Index == 7 {
		return map[string]any{"Index": 7, "wlEnable": enabled}
	}
	// The Guest editor maps its MoreSecure slider position to DAL enum255.
	payload := map[string]any{"Index": p.Index, "wlEnable": enabled, "SSID": p.SSID, "wlHide": p.WLHide, "wlEnableGuest": true, "wlGwMode": 1, "secMode": 255, "wpaMode": "wpa2psk", "owe": false, "AutoGenPSK": p.AutoGenPSK, "psk_value": p.PskDisplay, "encryp": p.Encryption, "RekeyingInterval": p.RekeyingInterval}
	for _, key := range []string{"upRate", "downRate", "MaxSessionPerGuestAPHost", "wlpmf", "RadiusServerPort", "RadiusSecret", "RadiusAccountingPort", "RadiusServerIPAddr", "X_ZYXEL_ReauthInterval", "X_ZYXEL_Preauth"} {
		if value, ok := p.Extra[key]; ok {
			payload[key] = value
		}
	}
	if p.Index == 3 {
		payload["div_wifiSubnet"] = true
		payload["subnetObjAction"] = action
		for key, value := range subnetValues(config) {
			payload[key] = value
		}
	}
	return payload
}

func verifyIoTSubnet(before, after bandSyncState, config *iotSubnetConfig, enabled7 bool) error {
	// JSON copies retain unknown fields without aliasing source snapshots.
	data, err := json.Marshal(before)
	if err != nil {
		return err
	}
	var expected bandSyncState
	if err := json.Unmarshal(data, &expected); err != nil {
		return err
	}
	for i := range expected.Profiles {
		p := &expected.Profiles[i]
		if p.Index == 7 {
			p.WLEnable = enabled7
			// BSSID is a runtime identity only shown for a broadcasting BSS.
			// Firmware clears/changes it when this requested target is disabled.
			// Restoring an enabled BSS still requires the original BSSID.
			if !enabled7 {
				for _, current := range after.Profiles {
					if current.Index == 7 && !current.WLEnable {
						p.Extra["BSSID"] = current.Extra["BSSID"]
						if _, present := current.Extra["BSSID"]; !present {
							delete(p.Extra, "BSSID")
						}
					}
				}
			}
		}
		if p.Index != 3 {
			continue
		}
		if config == nil {
			for _, key := range iotSubnetFields {
				delete(p.Extra, key)
			}
		} else {
			for key, value := range subnetValues(config) {
				p.Extra[key] = value
			}
			for _, current := range after.Profiles {
				if current.Index == 3 {
					if _, present := current.Extra["Interface"]; !present {
						delete(p.Extra, "Interface")
					}
				}
			}
		}
	}
	// A removed subnet may be represented by absent fields or explicit nulls.
	if config == nil {
		data, err = json.Marshal(after)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &after); err != nil {
			return err
		}
		for i := range after.Profiles {
			p := &after.Profiles[i]
			if p.Index != 3 {
				continue
			}
			if current, err := currentIoTSubnet(*p); err != nil || current != nil {
				return errors.New("IoT subnet removal was not verified")
			}
			for _, key := range iotSubnetFields {
				delete(p.Extra, key)
			}
		}
	}
	return verifyBandSync(expected, after, false, true)
}

// ConfigureIoTSubnet uses only IoT profiles: one routed 2.4 GHz BSS and a
// disabled 5 GHz BSS. It never changes the trusted LAN or global mesh settings.
func (a *App) ConfigureIoTSubnet(ctx context.Context, gateway, start, end string, disable, yes bool) (ConfigureResult, error) {
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	read := func(ctx context.Context, target *bandSyncState) error {
		return writer.Authenticate(ctx, func() error { var err error; *target, err = readBandSyncState(ctx, writer); return err })
	}
	var before bandSyncState
	if err := read(ctx, &before); err != nil {
		return ConfigureResult{}, err
	}
	targets, err := iotSubnetTargets(before)
	if err != nil {
		return ConfigureResult{}, err
	}
	original, err := currentIoTSubnet(targets[3])
	if err != nil {
		return ConfigureResult{}, err
	}
	var desired *iotSubnetConfig
	if !disable {
		desired, err = parseIoTSubnet(gateway, start, end, before.LAN)
		if err != nil {
			return ConfigureResult{}, err
		}
	}
	if original != nil && desired != nil && *original != *desired {
		return ConfigureResult{}, errors.New("remove the existing IoT subnet before changing its range")
	}
	if (original == nil && desired == nil) || (original != nil && desired != nil && *original == *desired && !targets[7].WLEnable) {
		return ConfigureResult{}, nil
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return ConfigureResult{}, errors.New("IoT subnet change requires interactive confirmation or --yes")
		}
		prompt := "Change only IoT 2.4 GHz subnet and disable IoT 5 GHz? Existing IoT client addresses will change."
		if disable {
			prompt = "Remove the IoT 2.4 GHz subnet and retain the current 5 GHz enable state? Existing IoT client addresses will change."
		}
		ok, err := a.output.Confirm(prompt)
		if err != nil {
			return ConfigureResult{}, err
		}
		if !ok {
			return ConfigureResult{}, errors.New("IoT subnet change not confirmed")
		}
	}
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return ConfigureResult{}, err
	}
	result := ConfigureResult{BackupDirectory: dir}
	backup, err := json.MarshalIndent(map[string]any{"model": SupportedModel, "firmware": SupportedFirmware, "subnet": original, "enabled_5ghz": targets[7].WLEnable}, "", "  ")
	if err != nil {
		return result, err
	}
	if err := store.WriteBackupFile(dir, "iot-subnet.json", append(backup, '\n')); err != nil {
		return result, err
	}
	if err := writer.Authenticate(ctx, func() error {
		data, err := writer.Download(ctx, "/cgi-bin/Backup_Restore?action=Backup")
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return errors.New("empty native backup")
		}
		return store.WriteBackupFile(dir, "router.config", data)
	}); err != nil {
		return result, err
	}
	var current bandSyncState
	if err := read(ctx, &current); err != nil {
		return result, err
	}
	if err := verifyIoTSubnet(before, current, original, targets[7].WLEnable); err != nil {
		return result, fmt.Errorf("IoT preflight changed: %w", err)
	}
	attempted := false
	put := func(ctx context.Context, payload map[string]any) error {
		if err := a.authenticateOnly(ctx, writer); err != nil {
			return err
		}
		attempted = true
		if err := writer.Put(ctx, "/cgi-bin/DAL?oid=wlan", payload); err != nil {
			return fmt.Errorf("update IoT profile %v: %w", payload["Index"], err)
		}
		return a.checkWLANAuthenticated(ctx, writer)
	}
	changeErr := error(nil)
	if !disable && targets[7].WLEnable {
		changeErr = put(ctx, buildIoTSubnetPayload(targets[7], false, nil, ""))
		if changeErr == nil {
			changeErr = read(ctx, &current)
		}
		if changeErr == nil {
			changeErr = verifyIoTSubnet(before, current, original, false)
		}
	}
	if changeErr == nil && !(original != nil && desired != nil && *original == *desired) {
		action := "POST"
		if disable {
			action = "DELETE"
		} else if original != nil {
			action = "PUT"
		}
		changeErr = put(ctx, buildIoTSubnetPayload(targets[3], true, desired, action))
	}
	if changeErr == nil {
		changeErr = read(ctx, &current)
	}
	enabled7 := targets[7].WLEnable
	if !disable {
		enabled7 = false
	}
	if changeErr == nil {
		changeErr = verifyIoTSubnet(before, current, desired, enabled7)
	}
	if changeErr == nil {
		result.Changed = true
		return result, nil
	}
	if !attempted {
		return result, changeErr
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rollbackErr := read(rollbackCtx, &current)
	if rollbackErr == nil {
		currentTargets, e := iotSubnetTargets(current)
		rollbackErr = e
		if rollbackErr == nil {
			actual, e := currentIoTSubnet(currentTargets[3])
			rollbackErr = e
			if rollbackErr == nil && ((original == nil) != (actual == nil) || (original != nil && actual != nil && *original != *actual)) {
				action := "DELETE"
				if original != nil {
					action = "POST"
					if actual != nil {
						action = "PUT"
					}
				}
				result.RollbackAttempted = true
				rollbackErr = put(rollbackCtx, buildIoTSubnetPayload(targets[3], true, original, action))
			}
			if rollbackErr == nil && currentTargets[7].WLEnable != targets[7].WLEnable {
				result.RollbackAttempted = true
				rollbackErr = put(rollbackCtx, buildIoTSubnetPayload(targets[7], targets[7].WLEnable, nil, ""))
			}
		}
	}
	if rollbackErr == nil {
		rollbackErr = read(rollbackCtx, &current)
	}
	if rollbackErr == nil {
		rollbackErr = verifyIoTSubnet(before, current, original, targets[7].WLEnable)
	}
	if rollbackErr != nil {
		return result, terminalWriteError{message: fmt.Sprintf("%v; IoT rollback failed: %v; backup %s", changeErr, rollbackErr, dir)}
	}
	result.RollbackVerified = true
	return result, terminalWriteError{message: fmt.Sprintf("%v; IoT rollback verified; backup %s", changeErr, dir)}
}
