package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"

	"github.com/nazar256/zyxelctl/internal/wifi"
)

const reservationPath = "/cgi-bin/DAL?oid=static_dhcp"

type dhcpSnapshot struct {
	Reservations []map[string]any
	LAN          []map[string]any
	Hosts        lanHostsResponse
	// SSID is the managed guest network name discovered from WLAN profiles.
	SSID string
	// GuestSubnet is the dedicated subnet on the guest profile pair, or an
	// invalid Prefix when the subnet feature is off.
	GuestSubnet netip.Prefix
}

func readDHCPState(ctx context.Context, api RouterAPI) (dhcpSnapshot, error) {
	var state dhcpSnapshot
	identity, err := api.ReadIdentity(ctx)
	if err != nil {
		return state, err
	}
	if err := requireSupportedIdentity(identity); err != nil {
		return state, err
	}
	for _, query := range []struct {
		path   string
		target *[]map[string]any
	}{
		{reservationPath, &state.Reservations}, {"/cgi-bin/DAL?oid=lan", &state.LAN},
	} {
		var response struct {
			Result string           `json:"result"`
			Object []map[string]any `json:"Object"`
		}
		if err := api.Get(ctx, query.path, &response); err != nil {
			return state, err
		}
		if response.Result != "ZCFG_SUCCESS" || (query.path != reservationPath && len(response.Object) == 0) {
			return state, fmt.Errorf("invalid DHCP response from %s", query.path)
		}
		*query.target = response.Object
	}
	if err := api.Get(ctx, "/cgi-bin/DAL?oid=lanhosts", &state.Hosts); err != nil {
		return state, err
	}
	var wlan wlanResponse
	if err := api.Get(ctx, "/cgi-bin/DAL?oid=wlan", &wlan); err != nil {
		return state, err
	}
	if wlan.Result != "ZCFG_SUCCESS" || len(wlan.Object) == 0 {
		return state, errors.New("invalid WLAN configuration")
	}
	if state.SSID, err = wifi.GuestPairSSID(wlan.Object); err != nil {
		return state, err
	}
	if state.GuestSubnet, err = wifi.GuestSubnet(wlan.Object); err != nil {
		return state, err
	}
	return state, nil
}

// bindingInGuestSubnet reports whether a reservation's address belongs to the
// managed guest subnet. An invalid prefix classifies every address as outside.
func bindingInGuestSubnet(record map[string]any, guest netip.Prefix) bool {
	if !guest.IsValid() {
		return false
	}
	text, _ := record["IPAddr"].(string)
	ip, err := netip.ParseAddr(text)
	return err == nil && guest.Contains(ip)
}

func iotReservation(state dhcpSnapshot, mac, address string) (map[string]any, error) {
	var selected map[string]any
	for _, record := range state.Reservations {
		recordMAC, _ := record["MACAddr"].(string)
		if strings.EqualFold(recordMAC, mac) {
			if selected != nil {
				return nil, errors.New("multiple reservations for this MAC")
			}
			selected = record
		} else if record["IPAddr"] == address {
			return nil, errors.New("address belongs to another reservation")
		}
	}
	if selected == nil {
		return nil, errors.New("an existing DHCP reservation is required; creating bindings is not supported")
	}
	index, ok := selected["Index"].(float64)
	if !ok || index < 1 || index != float64(int(index)) || selected["BrWan"] != "Default" || selected["Enable"] != true {
		return nil, errors.New("unsupported or disabled reservation")
	}
	indexCount := 0
	for _, record := range state.Reservations {
		if record["Index"] == index {
			indexCount++
		}
	}
	if indexCount != 1 {
		return nil, errors.New("ambiguous reservation index")
	}
	if len(state.LAN) != 1 || state.LAN[0]["Name"] != "Default" || state.LAN[0]["EnableDHCP"] != true || state.LAN[0]["DHCPType"] != "DHCPServer" {
		return nil, errors.New("requires the supported Default LAN DHCP server")
	}
	lanIP, _ := state.LAN[0]["IPAddress"].(string)
	maskText, _ := state.LAN[0]["SubnetMask"].(string)
	maskIP := net.ParseIP(maskText).To4()
	if maskIP == nil {
		return nil, errors.New("invalid LAN subnet mask")
	}
	mask := net.IPMask(maskIP)
	ones, bits := mask.Size()
	ip := net.ParseIP(address).To4()
	gateway := net.ParseIP(lanIP).To4()
	if gateway == nil || ip == nil || bits != 32 || ones < 1 || ones > 30 {
		return nil, errors.New("unsupported LAN subnet")
	}
	network := gateway.Mask(mask)
	broadcast := append(net.IP(nil), network...)
	for i := range broadcast {
		broadcast[i] |= ^mask[i]
	}
	if !(&net.IPNet{IP: network, Mask: mask}).Contains(ip) || ip.Equal(gateway) || ip.Equal(network) || ip.Equal(broadcast) {
		return nil, errors.New("address must be a usable client address in the current LAN subnet")
	}
	found := false
	for _, group := range state.Hosts.Object {
		for _, host := range group.Hosts {
			if !strings.EqualFold(host.MAC, mac) && host.IP == address {
				return nil, errors.New("address is still claimed by another client")
			}
			if strings.EqualFold(host.MAC, mac) && host.Active && host.Interface == "Wi-Fi" && host.WiFiName == state.SSID {
				found = true
			}
		}
	}
	if !found {
		return nil, errors.New("MAC must identify an active IoT Wi-Fi client")
	}
	return selected, nil
}

// ReserveIoTIP updates one existing binding. It does not renew the client or
// change the shared DHCP pool. Uncertain writes are never automatically replayed.
func (a *App) ReserveIoTIP(ctx context.Context, mac, address string, yes bool) (ConfigureResult, error) {
	return a.reserveIoTIP(ctx, mac, address, yes, false)
}

// RecreateIoTReservation uses the UI's delete/add flow for a binding whose
// normal edit is not honored. Other bindings may be renumbered by the router.
func (a *App) RecreateIoTReservation(ctx context.Context, mac, address string, yes bool) (ConfigureResult, error) {
	return a.reserveIoTIP(ctx, mac, address, yes, true)
}

type reservationWriter interface {
	RouterWriter
	Post(context.Context, string, any) error
	Delete(context.Context, string, any) error
}

func (a *App) reserveIoTIP(ctx context.Context, mac, address string, yes, recreate bool) (ConfigureResult, error) {
	hardware, err := net.ParseMAC(mac)
	if err != nil || len(hardware) != 6 || hardware[0]&1 != 0 || hardware.String() == "00:00:00:00:00:00" {
		return ConfigureResult{}, errors.New("a unicast six-byte MAC address is required")
	}
	mac = hardware.String()
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() {
		return ConfigureResult{}, errors.New("a valid IPv4 address is required")
	}
	address = ip.String()
	writer, store, err := a.writeDependencies()
	if err != nil {
		return ConfigureResult{}, err
	}
	var before dhcpSnapshot
	var original map[string]any
	err = writer.Authenticate(ctx, func() error {
		var err error
		before, err = readDHCPState(ctx, writer)
		if err != nil {
			return err
		}
		original, err = iotReservation(before, mac, address)
		if err == nil && recreate {
			if _, ok := writer.(reservationWriter); !ok {
				return errors.New("reservation recreation is unavailable")
			}
			if err := validateRecreateBinding(original); err != nil {
				return err
			}
			if _, err := bindingTable(before.Reservations); err != nil {
				return err
			}
		}
		return err
	})
	if err != nil {
		return ConfigureResult{}, err
	}
	if original["IPAddr"] == address && !recreate {
		return ConfigureResult{}, nil
	}
	if !yes {
		if !a.output.Interactive || a.output.Confirm == nil {
			return ConfigureResult{}, errors.New("reservation change requires interactive confirmation or --yes")
		}
		action := "Reserve"
		if recreate {
			action = "Delete and recreate the existing reservation as"
		}
		confirmed, err := a.output.Confirm(fmt.Sprintf("%s %s for IoT client %s (currently %v)?", action, address, mac, original["IPAddr"]))
		if err != nil {
			return ConfigureResult{}, err
		}
		if !confirmed {
			return ConfigureResult{}, errors.New("reservation change was not confirmed")
		}
	}
	dir, err := store.CreateBackupDir(a.output.Now())
	if err != nil {
		return ConfigureResult{}, err
	}
	result := ConfigureResult{BackupDirectory: dir}
	data, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		return result, err
	}
	if err := store.WriteBackupFile(dir, "dhcp-reservation.json", append(data, '\n')); err != nil {
		return result, err
	}
	// Revalidate after confirmation/backup so a concurrent administrator's changes
	// cannot be silently overwritten. Authentication callbacks contain reads only.
	err = writer.Authenticate(ctx, func() error {
		current, err := readDHCPState(ctx, writer)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before.Reservations, current.Reservations) || !reflect.DeepEqual(before.LAN, current.LAN) {
			return errors.New("DHCP configuration changed during preflight")
		}
		_, err = iotReservation(current, mac, address)
		return err
	})
	if err != nil {
		return result, err
	}
	if recreate {
		if err := recreateBinding(ctx, writer.(reservationWriter), before, original, address); err != nil {
			return result, fmt.Errorf("reservation recreation stopped; inspect current state before retrying; original binding backup in %s: %w", dir, err)
		}
		result.Changed = true
		return result, nil
	}
	payload := map[string]any{"Index": original["Index"], "BrWan": original["BrWan"], "Enable": true, "MACAddr": original["MACAddr"], "IPAddr": address}
	if err := writer.Put(ctx, reservationPath, payload); err != nil {
		return result, fmt.Errorf("reservation write failed; inspect state before retrying; original binding backup in %s: %w", dir, err)
	}
	var after dhcpSnapshot
	err = writer.Authenticate(ctx, func() error { var err error; after, err = readDHCPState(ctx, writer); return err })
	if err == nil {
		// Alter only the expected field in our detached snapshot, preserving unknown
		// fields and every other reservation for a complete read-back comparison.
		original["IPAddr"] = address
		if !reflect.DeepEqual(before.Reservations, after.Reservations) || !reflect.DeepEqual(before.LAN, after.LAN) {
			err = errors.New("reservation or unrelated DHCP configuration did not match the expected state")
		}
	}
	if err != nil {
		return result, fmt.Errorf("reservation verification failed; no automatic retry or rollback; original binding backup in %s: %w", dir, err)
	}
	result.Changed = true
	return result, nil
}

func validateRecreateBinding(record map[string]any) error {
	fields := []string{"Index", "BrWan", "Enable", "MACAddr", "IPAddr"}
	if len(record) != len(fields) {
		return errors.New("cannot recreate a reservation with unknown fields")
	}
	for _, field := range fields {
		if _, ok := record[field]; !ok {
			return fmt.Errorf("reservation is missing %s", field)
		}
	}
	index, indexOK := record["Index"].(float64)
	group, groupOK := record["BrWan"].(string)
	enabled, enabledOK := record["Enable"].(bool)
	mac, macOK := record["MACAddr"].(string)
	address, addressOK := record["IPAddr"].(string)
	ip, err := netip.ParseAddr(address)
	hardware, macErr := net.ParseMAC(mac)
	if !indexOK || index < 1 || index != float64(int(index)) || !groupOK || group != "Default" || !enabledOK || !enabled || !macOK || macErr != nil || len(hardware) != 6 || !addressOK || err != nil || !ip.Is4() {
		return errors.New("reservation has unsupported field types or values")
	}
	return nil
}

// bindingTable compares every field except the UI index, which the firmware
// renumbers after deleting a row. Duplicate MACs/indices are refused.
func bindingTable(records []map[string]any) (map[string]map[string]any, error) {
	table := make(map[string]map[string]any, len(records))
	indices := make(map[float64]bool, len(records))
	for _, record := range records {
		mac, _ := record["MACAddr"].(string)
		key := strings.ToLower(mac)
		index, ok := record["Index"].(float64)
		if key == "" || table[key] != nil || !ok || index < 1 || index != float64(int(index)) || indices[index] {
			return nil, errors.New("ambiguous DHCP reservation table")
		}
		indices[index] = true
		copy := make(map[string]any, len(record)-1)
		for field, value := range record {
			if field != "Index" {
				copy[field] = value
			}
		}
		table[key] = copy
	}
	return table, nil
}

func recreateBinding(ctx context.Context, writer reservationWriter, before dhcpSnapshot, original map[string]any, address string) error {
	expected, err := bindingTable(before.Reservations)
	if err != nil {
		return err
	}
	mac := original["MACAddr"].(string)
	key := strings.ToLower(mac)
	desired := expected[key]
	desired["IPAddr"] = address
	delete(expected, key)
	// Mutations are outside Authenticate, whose callback can be retried.
	if err := writer.Delete(ctx, reservationPath, map[string]any{"Index": original["Index"]}); err != nil {
		return fmt.Errorf("delete original binding: %w", err)
	}
	var deleted dhcpSnapshot
	err = writer.Authenticate(ctx, func() error {
		var err error
		deleted, err = readDHCPState(ctx, writer)
		if err != nil {
			return err
		}
		actual, err := bindingTable(deleted.Reservations)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(expected, actual) || !reflect.DeepEqual(before.LAN, deleted.LAN) {
			return errors.New("unexpected DHCP state after deleting the target binding")
		}
		return nil
	})
	if err != nil {
		return err
	}
	payload := map[string]any{"Index": float64(len(deleted.Reservations) + 1), "BrWan": original["BrWan"], "Enable": true, "MACAddr": mac, "IPAddr": address}
	// Check address claims and active IoT membership again before creation.
	candidate := deleted
	candidate.Reservations = append(append([]map[string]any(nil), deleted.Reservations...), payload)
	if _, err := iotReservation(candidate, mac, address); err != nil {
		return err
	}
	if err := writer.Post(ctx, reservationPath, payload); err != nil {
		return fmt.Errorf("create replacement binding: %w", err)
	}
	expected[key] = desired
	return writer.Authenticate(ctx, func() error {
		after, err := readDHCPState(ctx, writer)
		if err != nil {
			return err
		}
		actual, err := bindingTable(after.Reservations)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(expected, actual) || !reflect.DeepEqual(before.LAN, after.LAN) {
			return errors.New("recreated binding or unrelated DHCP state did not match")
		}
		return nil
	})
}
