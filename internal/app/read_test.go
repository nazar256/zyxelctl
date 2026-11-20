package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/session"
)

type fakeRouter struct {
	responses map[string]any
	authCalls int
	loginUser string
	getPaths  []string
	err       error
}

func (f *fakeRouter) Authenticate(_ context.Context, operation func() error) error {
	f.authCalls++
	if f.err != nil {
		return f.err
	}
	return operation()
}

func (f *fakeRouter) Login(_ context.Context, username string) error {
	f.loginUser = username
	return f.err
}

func (f *fakeRouter) ReadIdentity(ctx context.Context) (router.Identity, error) {
	var identity router.Identity
	err := f.Get(ctx, "/cgi-bin/getBasicInformation", &identity)
	return identity, err
}

func (f *fakeRouter) Get(_ context.Context, path string, target any) error {
	f.getPaths = append(f.getPaths, path)
	value, ok := f.responses[path]
	if !ok {
		return errors.New("unexpected path")
	}
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, target)
}

type fakeStore struct {
	state       session.State
	loadErr     error
	logoutCalls int
}

func (f *fakeStore) LoadState() (session.State, error) { return f.state, f.loadErr }
func (f *fakeStore) Logout() error {
	f.logoutCalls++
	return nil
}

func readFixtureRouter() *fakeRouter {
	return &fakeRouter{responses: map[string]any{
		"/cgi-bin/getBasicInformation": map[string]any{
			"ModelName": "EX5601-T1", "SoftwareVersion": "V5.70(ACEA.0)T56C_b29",
		},
		"/cgi-bin/DAL?oid=lan": map[string]any{
			"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"EnableDHCP": true}},
		},
		"/cgi-bin/DAL?oid=wlan": map[string]any{
			"result": "ZCFG_SUCCESS",
			"Object": []any{
				map[string]any{"Index": 1, "band": "2.4GHz", "wlEnable": true, "SSID": "Primary", "SecurityMode": "WPA2-Personal", "PskDisplay": "primary-secret"},
				map[string]any{"Index": 3, "band": "2.4GHz", "wlEnable": true, "oneSsidEnable": true, "SSID": "IoT-LAB", "SecurityMode": "WPA2-Personal", "PskDisplay": "iot-secret", "IsolationEnable": false, "X_ZYXEL_BssIdIsolation": true},
				map[string]any{"Index": 7, "band": "5GHz", "wlEnable": true, "oneSsidEnable": true, "SSID": "IoT-LAB", "SecurityMode": "WPA2-Personal", "PskDisplay": "iot-secret", "IsolationEnable": false, "X_ZYXEL_BssIdIsolation": true},
			},
		},
		"/custom": map[string]any{
			"result": "ZCFG_SUCCESS", "SSID": "IoT-LAB", "Password": "secret", "enabled": true,
		},
	}}
}

func TestInfoUsesAuthenticationAndReturnsIdentity(t *testing.T) {
	routerAPI := readFixtureRouter()
	application := New(routerAPI, &fakeStore{}, Output{})
	got, err := application.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := router.Identity{Model: "EX5601-T1", Firmware: "V5.70(ACEA.0)T56C_b29"}
	if got != want || routerAPI.authCalls != 1 {
		t.Fatalf("Info() = %#v, auth calls = %d", got, routerAPI.authCalls)
	}
}

func TestStatusSummarizesLANAndWLANHealth(t *testing.T) {
	routerAPI := readFixtureRouter()
	application := New(routerAPI, &fakeStore{}, Output{})
	got, err := application.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := StatusResult{
		Identity:        router.Identity{Model: "EX5601-T1", Firmware: "V5.70(ACEA.0)T56C_b29"},
		DHCPEnabled:     true,
		WLANProfiles:    3,
		EnabledProfiles: 3,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Status() = %#v, want %#v", got, want)
	}
}

func TestClientsListShowsOnlyActiveIPv4HostsWithAttachment(t *testing.T) {
	routerAPI := readFixtureRouter()
	routerAPI.responses["/cgi-bin/DAL?oid=lanhosts"] = map[string]any{
		"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"lanhosts": []any{
			map[string]any{"Active": true, "IPAddress": "192.168.1.214", "DeviceName": "iot-laptop", "PhysAddress": "02:11:22:33:44:55", "InterfaceType": "Wi-Fi", "WiFiname": "IoT-Lab", "SupportedFrequencyBands": "5GHz", "X_ZYXEL_ConnectedAP": "Gateway", "PskDisplay": "must-not-leak"},
			map[string]any{"Active": false, "IPAddress": "192.168.1.215", "DeviceName": "offline-phone", "PhysAddress": "02:aa:bb:cc:dd:ee"},
			map[string]any{"Active": true, "IPAddress": "", "DeviceName": "no-ip-yet"},
		}}},
	}
	application := New(routerAPI, &fakeStore{}, Output{})
	got, err := application.ClientsList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Client{{IP: "192.168.1.214", Name: "iot-laptop", MAC: "02:11:22:33:44:55", Interface: "Wi-Fi", WiFiName: "IoT-Lab", Band: "5GHz", AccessPoint: "Gateway"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ClientsList() = %#v, want %#v", got, want)
	}
}

func TestClientsListRejectsMissingHostTable(t *testing.T) {
	routerAPI := readFixtureRouter()
	routerAPI.responses["/cgi-bin/DAL?oid=lanhosts"] = map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{}}
	_, err := New(routerAPI, &fakeStore{}, Output{}).ClientsList(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no connected-device table") {
		t.Fatalf("ClientsList() error = %v", err)
	}
}

func TestWiFiClientsJoinsLiveMeshAssociationsToHostAddresses(t *testing.T) {
	routerAPI := readFixtureRouter()
	routerAPI.responses["/cgi-bin/DAL?oid=lanhosts"] = map[string]any{
		"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"lanhosts": []any{
			map[string]any{"Active": true, "IPAddress": "192.168.1.214", "DeviceName": "iot-laptop", "PhysAddress": "02:00:5e:00:00:33", "InterfaceType": "Wi-Fi", "X_ZYXEL_ConnectedAP": "02:00:5e:24:10:02"},
			map[string]any{"Active": true, "IPAddress": "192.168.1.215", "DeviceName": "iot-phone", "PhysAddress": "02:00:5e:00:00:44", "InterfaceType": "Wi-Fi", "X_ZYXEL_ConnectedAP": "02:00:5e:24:10:02"},
		}}},
	}
	routerAPI.responses["/cgi-bin/SteeringStatus_handle"] = []any{map[string]any{
		"mesh_value": true,
		"result_ctl": []any{},
		"result_ext": []any{
			map[string]any{"band": "5G", "bssid": "02:00:5e:24:10:01", "ssid": "IoT-Lab", "status": "Up"},
			map[string]any{"band": "2.4G", "bssid": "02:00:5e:24:00:02", "ssid": "IoT-Lab", "status": "Up"},
		},
		"result_sta": []any{
			map[string]any{"station": "02:00:5e:00:00:33", "bssid": "02:00:5e:24:10:01", "ssid": "IoT-Lab", "band": "2.4G/5G", "stale": "NO", "PskDisplay": "never-print"},
			map[string]any{"station": "02:00:5e:00:00:44", "bssid": "02:00:5e:24:00:02", "ssid": "IoT-Lab", "band": "2.4G/5G", "stale": "NO"},
			map[string]any{"station": "02:AA:BB:CC:DD:EE", "bssid": "02:00:5e:24:00:02", "ssid": "IoT-Lab", "stale": "YES"},
		},
	}}
	got, err := New(routerAPI, &fakeStore{}, Output{}).WiFiClients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []WiFiClient{
		{IP: "192.168.1.214", Name: "iot-laptop", MAC: "02:00:5e:00:00:33", SSID: "IoT-Lab", Band: "5GHz", BSSID: "02:00:5e:24:10:01", AccessPoint: "02:00:5e:24:10:02"},
		{IP: "192.168.1.215", Name: "iot-phone", MAC: "02:00:5e:00:00:44", SSID: "IoT-Lab", Band: "2.4GHz", BSSID: "02:00:5e:24:00:02", AccessPoint: "02:00:5e:24:10:02"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WiFiClients() = %#v, want %#v", got, want)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "never-print") || strings.Contains(string(encoded), "2.4G/5G") {
		t.Fatalf("WiFiClients() leaked secret or mislabeled capability as band: %s", encoded)
	}
}

func TestWiFiClientsRejectsMissingMeshTable(t *testing.T) {
	routerAPI := readFixtureRouter()
	routerAPI.responses["/cgi-bin/SteeringStatus_handle"] = []any{}
	_, err := New(routerAPI, &fakeStore{}, Output{}).WiFiClients(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no mesh station table") {
		t.Fatalf("WiFiClients() error = %v", err)
	}
}

func TestWiFiListOmitsPSKsAndDeviceIdentifiers(t *testing.T) {
	application := New(readFixtureRouter(), &fakeStore{}, Output{})
	got, err := application.WiFiList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(got)
	text := string(data)
	if strings.Contains(text, "secret") || strings.Contains(text, "Psk") {
		t.Fatalf("WiFiList leaked PSK: %s", text)
	}
	if !strings.Contains(text, "IoT-LAB") || !strings.Contains(text, "home_guest") {
		t.Fatalf("WiFiList omitted useful WLAN summary: %s", text)
	}
}

func TestIoTShowReturnsProfilesThreeAndSeven(t *testing.T) {
	application := New(readFixtureRouter(), &fakeStore{}, Output{})
	got, err := application.IoTShow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.SSID != "IoT-LAB" || !got.HomeGuest || len(got.Profiles) != 2 {
		t.Fatalf("IoTShow() = %#v", got)
	}
	if got.Profiles[0].Index != 3 || got.Profiles[1].Index != 7 {
		t.Fatalf("IoT profile indexes = %d,%d", got.Profiles[0].Index, got.Profiles[1].Index)
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), "iot-secret") {
		t.Fatalf("IoTShow leaked PSK: %s", data)
	}
}

func TestIoTShowReportsDisabledIndependentBand(t *testing.T) {
	a, r, _, _ := newWriteApp(t)
	r.before = r.after
	for i := range r.before {
		r.before[i].OneSSIDEnable = false
		if r.before[i].Index == 7 {
			r.before[i].WLEnable = false
		}
	}
	result, err := a.IoTShow(context.Background())
	if err != nil || len(result.Profiles) != 2 || result.Profiles[1].Enabled {
		t.Fatalf("inspection: %#v %v", result, err)
	}
}

func TestAPIGetRedactsSensitiveValuesByDefault(t *testing.T) {
	application := New(readFixtureRouter(), &fakeStore{}, Output{})
	got, err := application.APIGet(context.Background(), "/custom", false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"result": "ZCFG_SUCCESS", "SSID": "[redacted]", "Password": "[redacted]", "enabled": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("APIGet() = %#v, want %#v", got, want)
	}
}

func TestAPIGetSensitiveRequiresInteractiveConfirmation(t *testing.T) {
	for _, test := range []struct {
		name      string
		output    Output
		wantError string
		wantSSID  string
	}{
		{"non-interactive", Output{}, "interactive terminal", ""},
		{"declined", Output{Interactive: true, Confirm: func(string) (bool, error) { return false, nil }}, "not confirmed", ""},
		{"confirmed", Output{Interactive: true, Confirm: func(string) (bool, error) { return true, nil }}, "", "IoT-LAB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			application := New(readFixtureRouter(), &fakeStore{}, test.output)
			got, err := application.APIGet(context.Background(), "/custom", true)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil || got.(map[string]any)["SSID"] != test.wantSSID {
				t.Fatalf("got = %#v, error = %v", got, err)
			}
		})
	}
}

func TestAPIGetRejectsNonPathInput(t *testing.T) {
	application := New(readFixtureRouter(), &fakeStore{}, Output{})
	for _, path := range []string{"", "https://example.com", "relative", "//other-host/path"} {
		if _, err := application.APIGet(context.Background(), path, false); err == nil {
			t.Errorf("APIGet(%q) error = nil", path)
		}
	}
}

func TestSessionAndLogoutNeverAuthenticate(t *testing.T) {
	routerAPI := readFixtureRouter()
	loggedIn := time.Date(2024, 1, 2, 8, 0, 0, 0, time.UTC)
	store := &fakeStore{state: session.State{Model: "EX5601-T1", Firmware: "b29", LoggedInAt: loggedIn, AESKey: "secret-key", CSRFToken: "secret-token"}}
	application := New(routerAPI, store, Output{})
	got, err := application.Session()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Authenticated || got.Model != "EX5601-T1" || !got.LoggedInAt.Equal(loggedIn) {
		t.Fatalf("Session() = %#v", got)
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), "secret") {
		t.Fatalf("Session leaked secret: %s", data)
	}
	if err := application.Logout(); err != nil {
		t.Fatal(err)
	}
	if routerAPI.authCalls != 0 || store.logoutCalls != 1 {
		t.Fatalf("auth calls = %d, logout calls = %d", routerAPI.authCalls, store.logoutCalls)
	}
}

func TestSessionReportsMissingStateWithoutError(t *testing.T) {
	application := New(readFixtureRouter(), &fakeStore{loadErr: os.ErrNotExist}, Output{})
	got, err := application.Session()
	if err != nil {
		t.Fatal(err)
	}
	if got.Authenticated {
		t.Fatalf("Session() = %#v", got)
	}
}
