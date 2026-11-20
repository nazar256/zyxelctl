package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
)

type IoTReservation struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

type ClearReservationsResult struct {
	ConfigureResult
	DryRun     bool             `json:"dry_run"`
	Targets    []IoTReservation `json:"targets"`
	Deleted    []IoTReservation `json:"deleted"`
	Pending    []IoTReservation `json:"pending"`
	Kept       []IoTReservation `json:"kept"`
	Unverified *IoTReservation  `json:"unverified_delete,omitempty"`
	Unreserved []string         `json:"unreserved_clients"`
}

type clearReservationsState struct {
	dhcpSnapshot
	Members       map[string]bool
	VerifiedRadio map[string]bool
}

func readClearReservationsState(ctx context.Context, api RouterAPI) (clearReservationsState, error) {
	state := clearReservationsState{Members: make(map[string]bool), VerifiedRadio: make(map[string]bool)}
	var err error
	state.dhcpSnapshot, err = readDHCPState(ctx, api)
	if err != nil {
		return state, err
	}
	if len(state.Hosts.Object) == 0 {
		return state, errors.New("router returned no connected-device table")
	}
	var mesh []meshStatus
	if err := api.Get(ctx, "/cgi-bin/SteeringStatus_handle", &mesh); err != nil {
		return state, err
	}
	if len(mesh) == 0 {
		return state, errors.New("router returned no mesh station table")
	}
	radios := make(map[string]string)
	for _, group := range mesh {
		for _, radio := range append(group.ControllerRadios, group.ExtenderRadios...) {
			if strings.EqualFold(radio.Status, "Up") {
				key := strings.ToLower(radio.BSSID)
				if previous, ok := radios[key]; ok && previous != radio.SSID {
					return state, errors.New("conflicting mesh radio identities")
				}
				radios[key] = radio.SSID
			}
		}
	}
	otherNetworks := make(map[string]bool)
	for _, group := range mesh {
		for _, station := range group.Stations {
			if !strings.EqualFold(station.Stale, "NO") {
				continue
			}
			ssid := station.SSID
			mac, err := net.ParseMAC(station.MAC)
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
				return state, errors.New("invalid current station MAC")
			}
			key := mac.String()
			radioSSID, knownRadio := radios[strings.ToLower(station.BSSID)]
			if knownRadio && ssid != "" && ssid != radioSSID {
				return state, errors.New("station SSID conflicts with its active radio")
			}
			if ssid == "" {
				ssid = radioSSID
			}
			if ssid != state.SSID {
				otherNetworks[key] = true
				continue
			}
			state.Members[key] = true
			state.VerifiedRadio[key] = knownRadio && radioSSID == state.SSID
		}
	}
	for mac := range state.Members {
		if otherNetworks[mac] {
			return state, errors.New("IoT station also appears on another network")
		}
	}
	return state, nil
}

type reservationTarget struct {
	record map[string]any
	member bool
}

// normalizeExtraMACs validates explicit --mac selections. The active-client
// checks happen per snapshot in clearReservationTargets.
func normalizeExtraMACs(raw []string) ([]string, error) {
	seen := make(map[string]bool, len(raw))
	extras := make([]string, 0, len(raw))
	for _, value := range raw {
		hardware, err := net.ParseMAC(value)
		if err != nil || len(hardware) != 6 || hardware[0]&1 != 0 || hardware.String() == "00:00:00:00:00:00" {
			return nil, fmt.Errorf("invalid --mac address %q", value)
		}
		mac := hardware.String()
		if !seen[mac] {
			seen[mac] = true
			extras = append(extras, mac)
		}
	}
	return extras, nil
}

// clearReservationTargets selects bindings that do not belong to the IoT guest
// subnet: every member binding outside it plus each --mac binding outside it.
// Bindings already inside the guest subnet are returned in kept, never deleted.
func clearReservationTargets(state clearReservationsState, extras []string) ([]reservationTarget, []IoTReservation, error) {
	if _, err := bindingTable(state.Reservations); err != nil {
		return nil, nil, err
	}
	for mac := range state.Members {
		found := 0
		for _, group := range state.Hosts.Object {
			for _, host := range group.Hosts {
				if !strings.EqualFold(host.MAC, mac) || !host.Active {
					continue
				}
				// Mesh-agent host records omit WiFiname on b29. A known active
				// IoT BSSID supplies the missing SSID, never an explicit conflict.
				ssidOK := host.WiFiName == state.SSID || (host.WiFiName == "" && state.VerifiedRadio[mac])
				if host.Interface != "Wi-Fi" || !ssidOK {
					return nil, nil, errors.New("IoT binding has a conflicting active host identity")
				}
				found++
			}
		}
		if found != 1 {
			return nil, nil, errors.New("IoT station requires exactly one active IoT Wi-Fi host record")
		}
	}
	targets := make([]reservationTarget, 0)
	kept := make([]IoTReservation, 0)
	for _, record := range state.Reservations {
		text := record["MACAddr"].(string)
		hardware, err := net.ParseMAC(text)
		if err != nil || len(hardware) != 6 || !strings.EqualFold(text, hardware.String()) {
			return nil, nil, errors.New("unsupported DHCP binding MAC format")
		}
		mac := hardware.String()
		if !state.Members[mac] {
			continue
		}
		if bindingInGuestSubnet(record, state.GuestSubnet) {
			kept = append(kept, IoTReservation{MAC: text, IP: record["IPAddr"].(string)})
			continue
		}
		if err := validateRecreateBinding(record); err != nil {
			return nil, nil, fmt.Errorf("cannot safely back up IoT binding: %w", err)
		}
		targets = append(targets, reservationTarget{record: record, member: true})
	}
	for _, mac := range extras {
		// A member is already covered when bound; an unbound member has
		// nothing to delete and stays reported as unreserved.
		if state.Members[mac] {
			continue
		}
		active := false
		for _, group := range state.Hosts.Object {
			for _, host := range group.Hosts {
				if strings.EqualFold(host.MAC, mac) && host.Active {
					active = true
				}
			}
		}
		if active {
			return nil, nil, fmt.Errorf("client %s is active on the network; only offline devices may be cleared by --mac", mac)
		}
		var record map[string]any
		for _, candidate := range state.Reservations {
			text, _ := candidate["MACAddr"].(string)
			if strings.EqualFold(text, mac) {
				record = candidate
				break
			}
		}
		if record == nil {
			return nil, nil, fmt.Errorf("no DHCP reservation for --mac %s", mac)
		}
		if bindingInGuestSubnet(record, state.GuestSubnet) {
			kept = append(kept, IoTReservation{MAC: record["MACAddr"].(string), IP: record["IPAddr"].(string)})
			continue
		}
		if err := validateRecreateBinding(record); err != nil {
			return nil, nil, fmt.Errorf("cannot safely back up --mac %s binding: %w", mac, err)
		}
		targets = append(targets, reservationTarget{record: record})
	}
	return targets, kept, nil
}

// ClearIoTReservations deletes IoT bindings outside the guest subnet: the
// frozen set of current IoT bindings plus any bindings explicitly selected
// with --mac for fully offline devices. Bindings already inside the guest
// subnet are reported as kept and never deleted. Each deletion uses a fresh
// index and is verified before proceeding. Uncertain writes, recreated rows
// and unrelated changes stop the operation without replay.
func (a *App) ClearIoTReservations(ctx context.Context, dryRun, yes bool, extraMACs []string) (ClearReservationsResult, error) {
	result := ClearReservationsResult{DryRun: dryRun, Targets: []IoTReservation{}, Deleted: []IoTReservation{}, Pending: []IoTReservation{}, Kept: []IoTReservation{}, Unreserved: []string{}}
	extras, err := normalizeExtraMACs(extraMACs)
	if err != nil {
		return result, err
	}
	writer, store, err := a.writeDependencies()
	if err != nil {
		return result, err
	}
	deleter, ok := writer.(interface {
		Delete(context.Context, string, any) error
	})
	if !ok {
		return result, errors.New("DHCP reservation deletion is unavailable")
	}
	read := func() (clearReservationsState, error) {
		var state clearReservationsState
		err := writer.Authenticate(ctx, func() error {
			var err error
			state, err = readClearReservationsState(ctx, writer)
			return err
		})
		return state, err
	}
	before, err := read()
	if err != nil {
		return result, err
	}
	targets, kept, err := clearReservationTargets(before, extras)
	if err != nil {
		return result, err
	}
	for _, target := range targets {
		result.Targets = append(result.Targets, IoTReservation{MAC: target.record["MACAddr"].(string), IP: target.record["IPAddr"].(string)})
	}
	result.Kept = kept
	result.Pending = append(result.Pending, result.Targets...)
	bound := make(map[string]bool)
	for _, target := range result.Targets {
		bound[strings.ToLower(target.MAC)] = true
	}
	for _, reservation := range kept {
		bound[strings.ToLower(reservation.MAC)] = true
	}
	for mac := range before.Members {
		if !bound[mac] {
			result.Unreserved = append(result.Unreserved, mac)
		}
	}
	sort.Strings(result.Unreserved)
	if dryRun || len(targets) == 0 {
		return result, nil
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return result, errors.New("clearing IoT reservations requires interactive confirmation or --yes")
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("Delete %d existing DHCP reservations for %q clients? Clients must request new leases.", len(targets), before.SSID))
		if err != nil {
			return result, err
		}
		if !confirmed {
			return result, errors.New("reservation deletion was not confirmed")
		}
	}
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return result, err
	}
	result.BackupDirectory = dir
	bindings := make([]map[string]any, 0, len(targets))
	for _, target := range targets {
		bindings = append(bindings, target.record)
	}
	data, err := json.MarshalIndent(map[string]any{"bindings": bindings}, "", "  ")
	if err != nil {
		return result, err
	}
	if err := store.WriteBackupFile(dir, "iot-reservations.json", append(data, '\n')); err != nil {
		return result, err
	}
	stop := func(err error) (ClearReservationsResult, error) {
		partial, _ := json.Marshal(result)
		return result, fmt.Errorf("IoT reservation deletion stopped; inspect state before retrying; original bindings backup in %s; partial_result=%s: %w", dir, partial, err)
	}
	current, err := read()
	if err != nil {
		return stop(err)
	}
	currentTargets, currentKept, err := clearReservationTargets(current, extras)
	if err != nil {
		return stop(err)
	}
	if !reflect.DeepEqual(before.Reservations, current.Reservations) || !reflect.DeepEqual(before.LAN, current.LAN) || !reflect.DeepEqual(targets, currentTargets) || !reflect.DeepEqual(kept, currentKept) {
		return stop(errors.New("DHCP bindings or current IoT clients changed during preflight"))
	}
	expected, _ := bindingTable(before.Reservations)
	for i, target := range targets {
		current, err = read()
		if err != nil {
			return stop(err)
		}
		actual, err := bindingTable(current.Reservations)
		if err != nil {
			return stop(err)
		}
		if !reflect.DeepEqual(expected, actual) || !reflect.DeepEqual(before.LAN, current.LAN) {
			return stop(errors.New("DHCP state changed before the next deletion"))
		}
		key := strings.ToLower(target.record["MACAddr"].(string))
		if target.member && !current.Members[key] {
			return stop(errors.New("a selected client is no longer on IoT"))
		}
		// Membership, host identity and pending offline extras are checked
		// again after every prior delete.
		remaining := []string{}
		for _, t := range targets[i:] {
			if !t.member {
				remaining = append(remaining, strings.ToLower(t.record["MACAddr"].(string)))
			}
		}
		if _, _, err := clearReservationTargets(current, remaining); err != nil {
			return stop(err)
		}
		var index any
		for _, record := range current.Reservations {
			if text, _ := record["MACAddr"].(string); strings.EqualFold(text, key) {
				index = record["Index"]
				break
			}
		}
		if index == nil {
			return stop(errors.New("a selected binding disappeared before deletion"))
		}
		result.Unverified = &IoTReservation{MAC: result.Targets[i].MAC, IP: result.Targets[i].IP}
		if err := deleter.Delete(ctx, reservationPath, map[string]any{"Index": index}); err != nil {
			return stop(fmt.Errorf("delete request was not verified: %w", err))
		}
		delete(expected, key)
		current, err = read()
		if err != nil {
			return stop(err)
		}
		actual, err = bindingTable(current.Reservations)
		if err != nil {
			return stop(err)
		}
		if !reflect.DeepEqual(expected, actual) || !reflect.DeepEqual(before.LAN, current.LAN) {
			return stop(errors.New("deleted binding reappeared, deletion was ignored, or unrelated DHCP configuration changed"))
		}
		result.Deleted = append(result.Deleted, result.Targets[i])
		result.Pending = result.Pending[1:]
		result.Unverified = nil
		result.Changed = true
	}
	return result, nil
}
