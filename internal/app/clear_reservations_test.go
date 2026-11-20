package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nazar256/zyxelctl/internal/router"
)

type clearReservationsRouter struct {
	*reservationRouter
	mesh             []meshStatus
	meshReads        int
	moveOnRead       int
	moveAfterDelete  bool
	recreateOnRead   int
	reservationReads int
}

func (r *clearReservationsRouter) Get(ctx context.Context, path string, target any) error {
	if path != "/cgi-bin/SteeringStatus_handle" {
		if path == reservationPath {
			r.reservationReads++
			if r.reservationReads == r.recreateOnRead {
				r.records = append(r.records, map[string]any{"Index": float64(999), "BrWan": "Default", "Enable": true, "MACAddr": "02:00:5e:11:22:33", "IPAddr": "192.168.1.211"})
			}
		}
		return r.reservationRouter.Get(ctx, path, target)
	}
	r.meshReads++
	if r.meshReads == r.moveOnRead || (r.moveAfterDelete && r.deletes > 0) {
		r.mesh[0].Stations[1].SSID = "Trusted-Net"
	}
	data, _ := json.Marshal(r.mesh)
	return json.Unmarshal(data, target)
}

func newClearReservationsApp() (*App, *clearReservationsRouter, *backupStore) {
	_, base, store := newReservationApp()
	delete(base.records[0], "vendor_extension")
	base.records = append(base.records, map[string]any{"Index": float64(135), "BrWan": "Default", "Enable": true, "MACAddr": "02:00:00:00:00:90", "IPAddr": "192.168.1.216", "vendor_extension": "keep"})
	base.hosts = append(base.hosts,
		map[string]any{"Active": true, "PhysAddress": "02:00:5e:00:00:22", "IPAddress": "192.168.1.212", "InterfaceType": "Wi-Fi", "WiFiname": "IoT-Lab"},
		map[string]any{"Active": true, "PhysAddress": "02:00:00:00:00:90", "IPAddress": "192.168.1.216", "InterfaceType": "Wi-Fi", "WiFiname": "Trusted-Net"},
	)
	r := &clearReservationsRouter{reservationRouter: base, mesh: []meshStatus{{Stations: []meshStation{
		{MAC: "02:00:5e:11:22:33", SSID: "IoT-Lab", BSSID: "02:00:5e:24:00:01", Stale: "NO"},
		{MAC: "02:00:5e:00:00:22", SSID: "IoT-Lab", BSSID: "02:00:5e:24:00:02", Stale: "NO"},
		{MAC: "02:00:00:00:00:90", SSID: "Trusted-Net", Stale: "NO"},
	}}}}
	return New(r, store, Output{}), r, store
}

func TestClearIoTReservationsDeletesOnlyCurrentIoTAcrossRenumbering(t *testing.T) {
	a, r, store := newClearReservationsApp()
	result, err := a.ClearIoTReservations(context.Background(), false, true, nil)
	if err != nil || !result.Changed || len(result.Deleted) != 2 || len(result.Targets) != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(r.records) != 1 || r.records[0]["MACAddr"] != "02:00:00:00:00:90" || r.records[0]["IPAddr"] != "192.168.1.216" || r.records[0]["vendor_extension"] != "keep" {
		t.Fatalf("non-IoT binding not preserved: %#v", r.records)
	}
	backup := string(store.files["iot-reservations.json"])
	if !strings.Contains(backup, "192.168.1.211") || !strings.Contains(backup, "192.168.1.212") || strings.Contains(backup, "192.168.1.216") {
		t.Fatalf("unexpected backup: %s", backup)
	}
}

func TestClearIoTReservationsDryRunDoesNotWrite(t *testing.T) {
	a, r, store := newClearReservationsApp()
	result, err := a.ClearIoTReservations(context.Background(), true, false, nil)
	if err != nil || result.Changed || !result.DryRun || len(result.Targets) != 2 || len(result.Deleted) != 0 || r.deletes != 0 || len(store.files) != 0 {
		t.Fatalf("result=%+v err=%v writes=%d", result, err, r.deletes)
	}
}

func TestClearIoTReservationsStopsBeforeUnsafeDelete(t *testing.T) {
	for _, name := range []string{"wrong firmware", "unconfirmed", "backup failure", "unknown binding field", "duplicate MAC", "missing host", "conflicting host", "duplicate host", "moves during preflight", "unbound station missing host"} {
		t.Run(name, func(t *testing.T) {
			a, r, store := newClearReservationsApp()
			yes := true
			switch name {
			case "wrong firmware":
				r.identity.Firmware = "other"
			case "unconfirmed":
				yes = false
			case "backup failure":
				store.failFile = "iot-reservations.json"
			case "unknown binding field":
				r.records[0]["unknown"] = true
			case "duplicate MAC":
				r.records[1]["MACAddr"] = r.records[0]["MACAddr"]
			case "missing host":
				r.hosts[0]["Active"] = false
			case "conflicting host":
				r.hosts[0]["WiFiname"] = "Trusted-Net"
			case "duplicate host":
				r.hosts = append(r.hosts, r.hosts[0])
			case "unbound station missing host":
				r.mesh[0].Stations = append(r.mesh[0].Stations, meshStation{MAC: "02:00:00:00:00:99", SSID: "IoT-Lab", Stale: "NO"})
			case "moves during preflight":
				r.moveOnRead = 2
			}
			_, err := a.ClearIoTReservations(context.Background(), false, yes, nil)
			if err == nil || r.deletes != 0 {
				t.Fatalf("err=%v deletes=%d", err, r.deletes)
			}
		})
	}
}

func TestClearIoTReservationsStopsOnRecreationBetweenDeletes(t *testing.T) {
	a, r, _ := newClearReservationsApp()
	// Reads: initial, preflight, first pre-delete, first post-delete, next pre-delete.
	r.recreateOnRead = 5
	result, err := a.ClearIoTReservations(context.Background(), false, true, nil)
	if err == nil || r.deletes != 1 || len(result.Deleted) != 1 || len(result.Pending) != 1 || !strings.Contains(err.Error(), "partial_result=") || !strings.Contains(err.Error(), "192.168.1.212") {
		t.Fatalf("result=%+v err=%v deletes=%d", result, err, r.deletes)
	}
}

func TestClearIoTReservationsStopsAfterUnexpectedDelete(t *testing.T) {
	for _, name := range []string{"ignored delete", "auth failure", "unrelated change", "remaining client moves"} {
		t.Run(name, func(t *testing.T) {
			a, r, _ := newClearReservationsApp()
			wantDeleted := 0
			switch name {
			case "ignored delete":
				r.ignoreDelete = true
			case "auth failure":
				r.deleteErr = router.ErrUnauthenticated
			case "unrelated change":
				r.mutateOther = true
			case "remaining client moves":
				r.moveAfterDelete = true
				wantDeleted = 1
			}
			result, err := a.ClearIoTReservations(context.Background(), false, true, nil)
			if err == nil || r.deletes != 1 || len(result.Deleted) != wantDeleted || result.BackupDirectory == "" || !strings.Contains(err.Error(), "backup") {
				t.Fatalf("result=%+v err=%v deletes=%d", result, err, r.deletes)
			}
		})
	}
}

func TestClearIoTReservationsIgnoresStaleStationsAndNoopsWithoutBindings(t *testing.T) {
	a, r, store := newClearReservationsApp()
	r.mesh[0].Stations[0].Stale = "YES"
	r.mesh[0].Stations[1].Stale = "YES"
	result, err := a.ClearIoTReservations(context.Background(), false, true, nil)
	if err != nil || result.Changed || len(result.Targets) != 0 || r.deletes != 0 || len(store.files) != 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestClearIoTReservationsRejectsMalformedStationTable(t *testing.T) {
	a, r, _ := newClearReservationsApp()
	r.mesh[0].Stations[0].MAC = "not-a-mac"
	if _, err := a.ClearIoTReservations(context.Background(), true, false, nil); err == nil || r.deletes != 0 {
		t.Fatal(errors.New("invalid target MAC accepted"))
	}
}

func TestClearIoTReservationsRejectsConflictingStationIdentities(t *testing.T) {
	for _, name := range []string{"alternate MAC format", "radio disagrees"} {
		t.Run(name, func(t *testing.T) {
			a, r, _ := newClearReservationsApp()
			switch name {
			case "alternate MAC format":
				r.mesh[0].Stations = append(r.mesh[0].Stations, meshStation{MAC: "02-00-5E-11-22-33", SSID: "Trusted-Net", Stale: "NO"})
			case "radio disagrees":
				r.mesh[0].ControllerRadios = []meshRadio{{BSSID: "02:00:5e:24:00:01", SSID: "Trusted-Net", Status: "Up"}}
			}
			if _, err := a.ClearIoTReservations(context.Background(), false, true, nil); err == nil || r.deletes != 0 {
				t.Fatalf("conflicting selection accepted: %v", err)
			}
		})
	}
}

func TestClearIoTReservationsDeletesOfflineExtraMAC(t *testing.T) {
	a, r, _ := newClearReservationsApp()
	r.records = append(r.records, map[string]any{"Index": float64(140), "BrWan": "Default", "Enable": true, "MACAddr": "02:00:5e:00:00:33", "IPAddr": "192.168.1.214"})
	r.hosts = append(r.hosts, map[string]any{"Active": false, "PhysAddress": "02:00:5e:00:00:33", "IPAddress": "192.168.1.214", "InterfaceType": "Wi-Fi", "WiFiname": "IoT-Lab"})
	result, err := a.ClearIoTReservations(context.Background(), false, true, []string{"02:00:5e:00:00:33"})
	if err != nil || len(result.Deleted) != 3 || len(result.Pending) != 0 || len(r.records) != 1 {
		t.Fatalf("result=%+v err=%v records=%#v", result, err, r.records)
	}
	if result.Deleted[2].MAC != "02:00:5e:00:00:33" {
		t.Fatalf("explicit MAC was not deleted after member bindings: %#v", result.Deleted)
	}
}

func TestClearIoTReservationsExtraMACSafety(t *testing.T) {
	for _, name := range []string{"active on other network", "no binding", "member dedup", "invalid format"} {
		t.Run(name, func(t *testing.T) {
			a, r, _ := newClearReservationsApp()
			extra := ""
			wantDeletes := 0
			wantErr := name != "member dedup"
			switch name {
			case "active on other network":
				extra = "02:00:00:00:00:90"
			case "no binding":
				extra = "02:00:00:00:00:77"
			case "member dedup":
				extra = "02:00:5e:11:22:33"
				wantDeletes = 2
			case "invalid format":
				extra = "not-a-mac"
			}
			result, err := a.ClearIoTReservations(context.Background(), false, true, []string{extra})
			if wantErr && (err == nil || r.deletes != wantDeletes) {
				t.Fatalf("err=%v deletes=%d", err, r.deletes)
			}
			if !wantErr && (err != nil || len(result.Deleted) != wantDeletes || r.deletes != wantDeletes) {
				t.Fatalf("result=%+v err=%v deletes=%d", result, err, r.deletes)
			}
		})
	}
}

func TestClearIoTReservationsKeepsGuestSubnetBindings(t *testing.T) {
	a, r, _ := newClearReservationsApp()
	for i := range r.profiles {
		if r.profiles[i].Index == 3 {
			r.profiles[i].Extra["wlSubnetState"] = true
			r.profiles[i].Extra["LANIP"] = "10.99.0.1"
			r.profiles[i].Extra["SubnetMask"] = "255.255.255.0"
		}
	}
	r.records[0]["IPAddr"] = "10.99.0.50"
	r.hosts[0]["IPAddress"] = "10.99.0.50"
	r.records = append(r.records, map[string]any{"Index": float64(140), "BrWan": "Default", "Enable": true, "MACAddr": "02:00:5e:00:00:44", "IPAddr": "10.99.0.77"})
	r.hosts = append(r.hosts, map[string]any{"Active": false, "PhysAddress": "02:00:5e:00:00:44", "IPAddress": "10.99.0.77", "InterfaceType": "Wi-Fi", "WiFiname": "IoT-Lab"})
	result, err := a.ClearIoTReservations(context.Background(), false, true, []string{"02:00:5e:00:00:44"})
	if err != nil || len(result.Deleted) != 1 || result.Deleted[0].IP != "192.168.1.212" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(result.Kept) != 2 || result.Kept[0].IP != "10.99.0.50" || result.Kept[1].IP != "10.99.0.77" {
		t.Fatalf("kept=%#v", result.Kept)
	}
	if len(r.records) != 3 || len(result.Unreserved) != 0 {
		t.Fatalf("records=%#v unreserved=%#v", r.records, result.Unreserved)
	}
}

func TestClearIoTReservationsExtenderHostWithoutSSIDRequiresKnownIoTRadio(t *testing.T) {
	for _, known := range []bool{true, false} {
		a, r, _ := newClearReservationsApp()
		r.hosts[1]["WiFiname"] = ""
		if known {
			r.mesh[0].ExtenderRadios = []meshRadio{{BSSID: "02:00:5e:24:00:02", SSID: "IoT-Lab", Status: "Up"}}
		}
		result, err := a.ClearIoTReservations(context.Background(), true, false, nil)
		if known && (err != nil || len(result.Targets) != 2) {
			t.Fatalf("verified extender IoT identity refused: result=%+v err=%v", result, err)
		}
		if !known && err == nil {
			t.Fatal("unknown-radio empty-SSID host accepted")
		}
	}
}
