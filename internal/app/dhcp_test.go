package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type reservationRouter struct {
	identity     router.Identity
	records      []map[string]any
	hosts        []map[string]any
	lan          []map[string]any
	profiles     []wifi.Profile
	puts         []map[string]any
	putErr       error
	ignoreWrite  bool
	mutateOther  bool
	deletes      int
	posts        int
	deleteErr    error
	postErr      error
	ignoreDelete bool
}

func (r *reservationRouter) Delete(_ context.Context, path string, payload any) error {
	r.deletes++
	if path != reservationPath {
		return errors.New("unexpected delete path")
	}
	if r.deleteErr != nil {
		return r.deleteErr
	}
	if r.ignoreDelete {
		return nil
	}
	p := payload.(map[string]any)
	var remaining []map[string]any
	for _, record := range r.records {
		if record["Index"] != p["Index"] {
			remaining = append(remaining, record)
		}
	}
	r.records = remaining
	for i, record := range r.records {
		record["Index"] = float64(i + 1)
	}
	if r.mutateOther {
		r.records[0]["IPAddr"] = "192.168.1.217"
	}
	return nil
}

func (r *reservationRouter) Post(_ context.Context, path string, payload any) error {
	r.posts++
	if path != reservationPath {
		return errors.New("unexpected post path")
	}
	if r.postErr != nil {
		return r.postErr
	}
	data, _ := json.Marshal(payload)
	var p map[string]any
	_ = json.Unmarshal(data, &p)
	r.records = append(r.records, p)
	return nil
}

func TestRecreateIoTReservationPreservesOtherBindingsAcrossRenumbering(t *testing.T) {
	a, r, s := newReservationApp()
	delete(r.records[0], "vendor_extension")
	result, err := a.RecreateIoTReservation(context.Background(), "02:00:5e:11:22:33", "192.168.1.220", true)
	if err != nil || !result.Changed || r.deletes != 1 || r.posts != 1 || len(r.puts) != 0 {
		t.Fatalf("result=%+v err=%v writes=%d/%d", result, err, r.deletes, r.posts)
	}
	if r.records[0]["MACAddr"] != "02:00:5e:00:00:22" || r.records[0]["IPAddr"] != "192.168.1.212" || r.records[1]["IPAddr"] != "192.168.1.220" {
		t.Fatalf("bindings changed: %#v", r.records)
	}
	if !strings.Contains(string(s.files["dhcp-reservation.json"]), "192.168.1.211") {
		t.Fatal("original reservation not backed up")
	}
}

func TestRecreateIoTReservationStopsOnUncertainOrUnexpectedState(t *testing.T) {
	for _, name := range []string{"delete auth error", "post auth error", "ignored delete", "unrelated change", "unknown target field", "replaced address key", "wrong address type", "backup failure"} {
		t.Run(name, func(t *testing.T) {
			a, r, s := newReservationApp()
			delete(r.records[0], "vendor_extension")
			wantDeletes, wantPosts := 1, 0
			switch name {
			case "delete auth error":
				r.deleteErr = router.ErrUnauthenticated
			case "post auth error":
				r.postErr = router.ErrUnauthenticated
				wantPosts = 1
			case "ignored delete":
				r.ignoreDelete = true
			case "unrelated change":
				r.mutateOther = true
			case "unknown target field":
				r.records[0]["extra"] = "must not drop"
				wantDeletes = 0
			case "replaced address key":
				delete(r.records[0], "IPAddr")
				r.records[0]["extra"] = "must not drop"
				wantDeletes = 0
			case "wrong address type":
				r.records[0]["IPAddr"] = float64(129)
				wantDeletes = 0
			case "backup failure":
				s.failFile = "dhcp-reservation.json"
				wantDeletes = 0
			}
			_, err := a.RecreateIoTReservation(context.Background(), "02:00:5e:11:22:33", "192.168.1.220", true)
			if err == nil || r.deletes != wantDeletes || r.posts != wantPosts {
				t.Fatalf("err=%v writes=%d/%d", err, r.deletes, r.posts)
			}
		})
	}
}

func (r *reservationRouter) Authenticate(_ context.Context, op func() error) error { return op() }
func (r *reservationRouter) Login(context.Context, string) error                   { return nil }
func (r *reservationRouter) ReadIdentity(context.Context) (router.Identity, error) {
	return r.identity, nil
}
func (r *reservationRouter) Download(context.Context, string) ([]byte, error) {
	return nil, errors.New("unexpected download")
}
func (r *reservationRouter) Get(_ context.Context, path string, target any) error {
	var object any
	switch path {
	case "/cgi-bin/DAL?oid=static_dhcp":
		object = r.records
	case "/cgi-bin/DAL?oid=lan":
		object = r.lan
	case "/cgi-bin/DAL?oid=lanhosts":
		object = []any{map[string]any{"lanhosts": r.hosts}}
	case "/cgi-bin/DAL?oid=wlan":
		object = r.profiles
	default:
		return fmt.Errorf("unexpected GET %s", path)
	}
	data, _ := json.Marshal(map[string]any{"result": "ZCFG_SUCCESS", "Object": object})
	return json.Unmarshal(data, target)
}
func (r *reservationRouter) Put(_ context.Context, path string, payload any) error {
	if path != "/cgi-bin/DAL?oid=static_dhcp" {
		return fmt.Errorf("unexpected PUT %s", path)
	}
	data, _ := json.Marshal(payload)
	var p map[string]any
	_ = json.Unmarshal(data, &p)
	r.puts = append(r.puts, p)
	if r.putErr != nil {
		return r.putErr
	}
	if !r.ignoreWrite {
		for _, record := range r.records {
			if record["Index"] == p["Index"] {
				record["IPAddr"] = p["IPAddr"]
			}
		}
	}
	if r.mutateOther {
		r.records[1]["IPAddr"] = "192.168.1.217"
	}
	return nil
}

func newReservationApp() (*App, *reservationRouter, *backupStore) {
	events := []string{}
	r := &reservationRouter{
		identity: router.Identity{Model: SupportedModel, Firmware: SupportedFirmware},
		records: []map[string]any{
			{"Index": float64(133), "BrWan": "Default", "Enable": true, "MACAddr": "02:00:5e:11:22:33", "IPAddr": "192.168.1.211", "vendor_extension": "preserved"},
			{"Index": float64(134), "BrWan": "Default", "Enable": true, "MACAddr": "02:00:5e:00:00:22", "IPAddr": "192.168.1.212"},
		},
		lan:   []map[string]any{{"Name": "Default", "IPAddress": "192.168.1.1", "SubnetMask": "255.255.255.0", "EnableDHCP": true, "DHCPType": "DHCPServer"}},
		hosts: []map[string]any{{"Active": true, "PhysAddress": "02:00:5e:11:22:33", "IPAddress": "192.168.1.211", "InterfaceType": "Wi-Fi", "WiFiname": "IoT-Lab"}},
		profiles: []wifi.Profile{
			{Index: 1, Band: "2.4GHz", WLEnable: true, SSID: "Trusted-Net", Extra: map[string]any{"MainSSID": true}},
			{Index: 3, Band: "2.4GHz", WLEnable: true, SSID: "IoT-Lab", Extra: map[string]any{"MainSSID": false}},
			{Index: 7, Band: "5GHz", WLEnable: true, SSID: "IoT-Lab", Extra: map[string]any{"MainSSID": false}},
		},
	}
	s := &backupStore{root: "backup", events: &events}
	return New(r, s, Output{}), r, s
}

func TestReserveIoTIPChangesOneExistingBindingAndNoops(t *testing.T) {
	a, r, s := newReservationApp()
	result, err := a.ReserveIoTIP(context.Background(), "02:00:5e:11:22:33", "192.168.1.220", true)
	if err != nil || !result.Changed {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	want := map[string]any{"Index": float64(133), "BrWan": "Default", "Enable": true, "MACAddr": "02:00:5e:11:22:33", "IPAddr": "192.168.1.220"}
	if len(r.puts) != 1 || !reflect.DeepEqual(r.puts[0], want) {
		t.Fatalf("unexpected writes: %#v", r.puts)
	}
	if !strings.Contains(string(s.files["dhcp-reservation.json"]), "192.168.1.211") {
		t.Fatal("missing original binding backup")
	}
	result, err = a.ReserveIoTIP(context.Background(), "02:00:5e:11:22:33", "192.168.1.220", true)
	if err != nil || result.Changed || len(r.puts) != 1 {
		t.Fatalf("not a no-op: %+v %v", result, err)
	}
}

func TestReserveIoTIPRefusesUnsafeChanges(t *testing.T) {
	for _, name := range []string{"wrong firmware", "wrong SSID", "wired", "inactive", "duplicate reservation", "occupied IP", "missing reservation", "invalid MAC", "multicast MAC", "outside subnet", "router address", "broadcast", "disabled DHCP", "confirmation", "backup failure"} {
		t.Run(name, func(t *testing.T) {
			a, r, s := newReservationApp()
			mac, ip, yes := "02:00:5e:11:22:33", "192.168.1.220", true
			switch name {
			case "wrong firmware":
				r.identity.Firmware = "other"
			case "wrong SSID":
				r.hosts[0]["WiFiname"] = "Trusted-Net"
			case "wired":
				r.hosts[0]["InterfaceType"] = "Ethernet"
			case "inactive":
				r.hosts[0]["Active"] = false
			case "duplicate reservation":
				r.records[1]["IPAddr"] = ip
			case "occupied IP":
				r.hosts = append(r.hosts, map[string]any{"Active": true, "PhysAddress": "02:00:5e:00:00:77", "IPAddress": ip})
			case "missing reservation":
				r.records = r.records[1:]
			case "invalid MAC":
				mac = "bad"
			case "multicast MAC":
				mac = "03:00:5e:00:00:77"
			case "outside subnet":
				ip = "192.168.2.111"
			case "router address":
				ip = "192.168.1.1"
			case "broadcast":
				ip = "192.168.1.255"
			case "disabled DHCP":
				r.lan[0]["EnableDHCP"] = false
			case "confirmation":
				yes = false
			case "backup failure":
				s.failFile = "dhcp-reservation.json"
			}
			_, err := a.ReserveIoTIP(context.Background(), mac, ip, yes)
			if err == nil || len(r.puts) != 0 {
				t.Fatalf("unsafe write accepted: %v %#v", err, r.puts)
			}
		})
	}
}

func TestReserveIoTIPVerifiesTableAndNeverReplaysUncertainWrite(t *testing.T) {
	for _, name := range []string{"ignored", "unrelated change", "authentication failure"} {
		t.Run(name, func(t *testing.T) {
			a, r, _ := newReservationApp()
			switch name {
			case "ignored":
				r.ignoreWrite = true
			case "unrelated change":
				r.mutateOther = true
			case "authentication failure":
				r.putErr = router.ErrUnauthenticated
			}
			result, err := a.ReserveIoTIP(context.Background(), "02:00:5e:11:22:33", "192.168.1.220", true)
			if err == nil || result.Changed || len(r.puts) != 1 || !strings.Contains(err.Error(), "backup") {
				t.Fatalf("result=%+v err=%v writes=%d", result, err, len(r.puts))
			}
		})
	}
}
