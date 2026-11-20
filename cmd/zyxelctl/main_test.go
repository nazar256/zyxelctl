package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nazar256/zyxelctl/internal/app"
	"github.com/nazar256/zyxelctl/internal/router"
)

type commandServiceStub struct {
	called string
	err    error
}

func (s *commandServiceStub) ConfigureIoTSubnet(_ context.Context, gateway, start, end string, disable, yes bool) (app.ConfigureResult, error) {
	s.called = fmt.Sprintf("iot subnet %s %s %s %t %t", gateway, start, end, disable, yes)
	return app.ConfigureResult{}, s.err
}

func TestIoTSubnetCommand(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"iot", "subnet", "--gateway", "10.99.0.1/24", "--dhcp-start", "10.99.0.2", "--dhcp-end", "10.99.0.100", "--yes"}, "iot subnet 10.99.0.1/24 10.99.0.2 10.99.0.100 false true"},
		{[]string{"iot", "subnet", "--disable", "--yes"}, "iot subnet    true true"},
	} {
		s := &commandServiceStub{}
		var out, stderr bytes.Buffer
		if code := execute(context.Background(), tc.args, s, &out, &stderr); code != 0 || s.called != tc.want {
			t.Fatalf("code=%d call=%s err=%s", code, s.called, stderr.String())
		}
	}
	for _, args := range [][]string{{"iot", "subnet"}, {"iot", "subnet", "--gateway", "10.99.0.1/24"}, {"iot", "subnet", "--disable", "--gateway", "10.99.0.1/24"}} {
		s := &commandServiceStub{}
		var out, stderr bytes.Buffer
		if execute(context.Background(), args, s, &out, &stderr) != 2 || s.called != "" {
			t.Fatalf("bad flags accepted %v", args)
		}
	}
	if _, _, err := parseDeviceArgs([]string{"--device", "extender", "iot", "subnet", "--disable"}); err == nil {
		t.Fatal("gateway-only subnet write accepted on extender")
	}
}

func (s *commandServiceStub) SetBandSync(_ context.Context, enabled, yes bool) (app.ConfigureResult, error) {
	s.called = fmt.Sprintf("wifi band-sync %t %t", enabled, yes)
	return app.ConfigureResult{}, s.err
}

func TestBandSyncCommand(t *testing.T) {
	for _, enabled := range []string{"true", "false"} {
		service := &commandServiceStub{}
		var out, stderr bytes.Buffer
		args := []string{"wifi", "band-sync", "--enabled=" + enabled, "--yes"}
		if code := execute(context.Background(), args, service, &out, &stderr); code != 0 || service.called != "wifi band-sync "+enabled+" true" {
			t.Fatalf("code=%d call=%s err=%s", code, service.called, stderr.String())
		}
	}
	for _, args := range [][]string{{"wifi", "band-sync"}, {"wifi", "band-sync", "--enabled=bad"}, {"wifi", "band-sync", "--enabled=false", "extra"}} {
		service := &commandServiceStub{}
		var out, stderr bytes.Buffer
		if execute(context.Background(), args, service, &out, &stderr) != 2 || service.called != "" {
			t.Fatalf("unsafe flags accepted %v", args)
		}
	}
	if _, _, err := parseDeviceArgs([]string{"--device", "extender", "wifi", "band-sync", "--enabled=false", "--yes"}); err == nil {
		t.Fatal("extender global toggle accepted")
	}
}

func TestReservationRequiresMACAndIP(t *testing.T) {
	for _, args := range [][]string{{"iot", "reserve-ip"}, {"iot", "reserve-ip", "--ip", "192.168.1.220"}, {"iot", "reserve-ip", "--mac", "02:00:5e:11:22:33"}} {
		service := &commandServiceStub{}
		var stdout, stderr bytes.Buffer
		if code := execute(context.Background(), args, service, &stdout, &stderr); code != 2 || service.called != "" {
			t.Fatalf("code=%d call=%s", code, service.called)
		}
	}
	if _, _, err := parseDeviceArgs([]string{"--device", "extender", "iot", "reserve-ip", "--mac", "02:00:5e:11:22:33", "--ip", "192.168.1.220", "--yes"}); err == nil {
		t.Fatal("extender reservation mutation accepted")
	}
}

func (s *commandServiceStub) Login(context.Context, string) error { s.called = "login"; return s.err }
func (s *commandServiceStub) Logout() error                       { s.called = "logout"; return s.err }
func (s *commandServiceStub) Session() (app.SessionResult, error) {
	s.called = "session"
	return app.SessionResult{Authenticated: true, Model: "EX5601-T1"}, s.err
}
func (s *commandServiceStub) Info(context.Context) (router.Identity, error) {
	s.called = "info"
	return router.Identity{Model: "EX5601-T1", Firmware: "b29"}, s.err
}
func (s *commandServiceStub) Status(context.Context) (app.StatusResult, error) {
	s.called = "status"
	return app.StatusResult{}, s.err
}
func (s *commandServiceStub) WiFiList(context.Context) ([]app.WiFiSummary, error) {
	s.called = "wifi list"
	return nil, s.err
}
func (s *commandServiceStub) ClientsList(context.Context) ([]app.Client, error) {
	s.called = "clients list"
	return []app.Client{{IP: "192.168.1.214", Interface: "Wi-Fi"}}, s.err
}
func (s *commandServiceStub) WiFiClients(context.Context) ([]app.WiFiClient, error) {
	s.called = "clients wifi"
	return []app.WiFiClient{{IP: "192.168.1.214", SSID: "IoT-Lab", MAC: "02:11:22:33:44:55"}}, s.err
}
func (s *commandServiceStub) IoTShow(context.Context) (app.IoTResult, error) {
	s.called = "iot show"
	return app.IoTResult{}, s.err
}
func (s *commandServiceStub) APIGet(_ context.Context, _ string, _ bool) (any, error) {
	s.called = "api get"
	return map[string]any{"ok": true}, s.err
}
func (s *commandServiceStub) ConfigBackup(context.Context, string) (app.BackupResult, error) {
	s.called = "config backup"
	return app.BackupResult{}, s.err
}
func (s *commandServiceStub) WiFiSnapshot(context.Context, string) (app.BackupResult, error) {
	s.called = "wifi snapshot"
	return app.BackupResult{}, s.err
}
func (s *commandServiceStub) WiFiRestore(context.Context, string, bool) (app.ConfigureResult, error) {
	s.called = "wifi restore"
	return app.ConfigureResult{}, s.err
}
func (s *commandServiceStub) ConfigureIoT(context.Context, string, bool) (app.ConfigureResult, error) {
	s.called = "iot configure"
	return app.ConfigureResult{}, s.err
}
func (s *commandServiceStub) EnableIoTPeerAccess(context.Context, bool) (app.ConfigureResult, error) {
	s.called = "iot allow-peers"
	return app.ConfigureResult{}, s.err
}
func (s *commandServiceStub) SetExtenderIoTHomeGuest(context.Context, bool) (app.ConfigureResult, error) {
	s.called = "iot home-guest"
	return app.ConfigureResult{}, s.err
}
func (s *commandServiceStub) SetIoTBroadcast(_ context.Context, enabled, yes bool) (app.ConfigureResult, error) {
	s.called = fmt.Sprintf("iot broadcast %t %t", enabled, yes)
	return app.ConfigureResult{}, s.err
}

func TestBroadcastDispatch(t *testing.T) {
	for _, enabled := range []string{"true", "false"} {
		for _, args := range [][]string{
			{"iot", "broadcast", "--enabled=" + enabled, "--yes"},
			{"--device", "extender", "iot", "broadcast", "--enabled=" + enabled, "--yes"},
		} {
			_, command, err := parseDeviceArgs(args)
			if err != nil {
				t.Fatalf("parse %v: %v", args, err)
			}
			service := &commandServiceStub{}
			var out, stderr bytes.Buffer
			if code := execute(context.Background(), command, service, &out, &stderr); code != 0 || service.called != "iot broadcast "+enabled+" true" {
				t.Fatalf("code=%d call=%s err=%s", code, service.called, stderr.String())
			}
		}
	}
	for _, args := range [][]string{{"iot", "broadcast"}, {"iot", "broadcast", "--enabled=perhaps"}, {"--device", "extender", "iot", "broadcast"}, {"--device", "extender", "iot", "broadcast", "--enabled=perhaps"}} {
		_, command, err := parseDeviceArgs(args)
		if err != nil {
			continue
		}
		service := &commandServiceStub{}
		var out, stderr bytes.Buffer
		if execute(context.Background(), command, service, &out, &stderr) != 2 || service.called != "" {
			t.Fatalf("unsafe command accepted: %v", args)
		}
	}
}
func (s *commandServiceStub) ReserveIoTIP(_ context.Context, mac, ip string, yes bool) (app.ConfigureResult, error) {
	s.called = fmt.Sprintf("iot reserve-ip %s %s %t", mac, ip, yes)
	return app.ConfigureResult{}, s.err
}

func (s *commandServiceStub) ClearIoTReservations(_ context.Context, dryRun, yes bool, macs []string) (app.ClearReservationsResult, error) {
	s.called = fmt.Sprintf("iot clear-reservations %t %t %v", dryRun, yes, macs)
	return app.ClearReservationsResult{}, nil
}
func (s *commandServiceStub) RestartIoTRadio(_ context.Context, yes bool) (app.RadioRestartResult, error) {
	s.called = fmt.Sprintf("iot radio-restart %t", yes)
	return app.RadioRestartResult{}, s.err
}

func TestClearReservationsCLIRejectsUnknownArgumentsAndExtender(t *testing.T) {
	for _, args := range [][]string{
		{"iot", "clear-reservations", "unexpected"},
		{"iot", "clear-reservations", "--all"},
		{"iot", "clear-reservations", "--mac", "not-a-mac"},
		{"iot", "radio-restart", "unexpected"},
	} {
		s := &commandServiceStub{}
		var stdout, stderr bytes.Buffer
		if execute(context.Background(), args, s, &stdout, &stderr) == 0 || s.called != "" {
			t.Fatalf("unsafe arguments accepted: %v", args)
		}
	}
	for _, args := range [][]string{
		{"--device", "extender", "iot", "clear-reservations", "--yes"},
		{"--device", "extender", "iot", "reserve-ip", "--mac", "02:00:5e:00:00:01", "--ip", "192.168.1.210"},
	} {
		if _, _, err := parseDeviceArgs(args); err == nil {
			t.Fatalf("extender mutation accepted: %v", args)
		}
	}
}
func (s *commandServiceStub) RecreateIoTReservation(_ context.Context, mac, ip string, yes bool) (app.ConfigureResult, error) {
	s.called = fmt.Sprintf("iot reserve-ip --recreate %s %s %t", mac, ip, yes)
	return app.ConfigureResult{}, s.err
}
func (s *commandServiceStub) ProbeIoTIsolation(context.Context, string, bool) (app.IsolationProbeResult, error) {
	s.called = "iot probe-isolation"
	return app.IsolationProbeResult{RollbackVerified: true}, s.err
}

func TestReadCommandsDispatchAndEmitJSON(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"session"}, "session"},
		{[]string{"info"}, "info"},
		{[]string{"status"}, "status"},
		{[]string{"wifi", "list"}, "wifi list"},
		{[]string{"clients", "list"}, "clients list"},
		{[]string{"clients", "wifi"}, "clients wifi"},
		{[]string{"wifi", "snapshot"}, "wifi snapshot"},
		{[]string{"wifi", "restore", "/tmp/snapshot.json", "--yes"}, "wifi restore"},
		{[]string{"iot", "show"}, "iot show"},
		{[]string{"iot", "configure", "--ssid", "IoT-Lab", "--yes"}, "iot configure"},
		{[]string{"iot", "allow-peers", "--yes"}, "iot allow-peers"},
		{[]string{"iot", "reserve-ip", "--mac", "02:00:5e:11:22:33", "--ip", "192.168.1.220", "--yes"}, "iot reserve-ip 02:00:5e:11:22:33 192.168.1.220 true"},
		{[]string{"iot", "reserve-ip", "--mac", "02:00:5e:11:22:33", "--ip", "192.168.1.220", "--yes", "--recreate"}, "iot reserve-ip --recreate 02:00:5e:11:22:33 192.168.1.220 true"},
		{[]string{"iot", "clear-reservations", "--yes"}, "iot clear-reservations false true []"},
		{[]string{"iot", "clear-reservations", "--dry-run"}, "iot clear-reservations true false []"},
		{[]string{"iot", "clear-reservations", "--mac", "02:00:5e:00:00:33", "--mac", "02:00:5e:00:00:44", "--yes"}, "iot clear-reservations false true [02:00:5e:00:00:33 02:00:5e:00:00:44]"},
		{[]string{"iot", "radio-restart", "--yes"}, "iot radio-restart true"},
		{[]string{"iot", "probe-isolation", "--target", "http://192.168.1.214:9876/", "--yes"}, "iot probe-isolation"},
		{[]string{"config", "backup"}, "config backup"},
		{[]string{"api", "get", "/custom"}, "api get"},
		{[]string{"logout"}, "logout"},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.args, "_"), func(t *testing.T) {
			service := &commandServiceStub{}
			var stdout, stderr bytes.Buffer
			exitCode := execute(context.Background(), test.args, service, &stdout, &stderr)
			if exitCode != 0 || service.called != test.want {
				t.Fatalf("exit = %d, called = %q, stderr = %q", exitCode, service.called, stderr.String())
			}
			if !strings.HasSuffix(stdout.String(), "\n") || !json.Valid(stdout.Bytes()) {
				t.Fatalf("stdout is not newline-terminated JSON: %q", stdout.String())
			}
		})
	}
}

func TestLoginDispatchesDefaultAndExplicitUsername(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"login"}, "admin"},
		{[]string{"login", "--username", "operator"}, "operator"},
	} {
		service := &commandServiceStub{}
		var stdout, stderr bytes.Buffer
		captured := ""
		wrapped := loginCaptureService{commandServiceStub: service, username: &captured}
		if exit := execute(context.Background(), test.args, &wrapped, &stdout, &stderr); exit != 0 {
			t.Fatalf("execute() = %d, stderr = %q", exit, stderr.String())
		}
		if captured != test.want {
			t.Fatalf("username = %q, want %q", captured, test.want)
		}
	}
}

type textPromptStub struct {
	value string
	calls int
}

func (p *textPromptStub) Text(_, fallback string) (string, error) {
	p.calls++
	if p.value == "" {
		return fallback, nil
	}
	return p.value, nil
}

func TestLoginUsernamePromptUsesAdminDefaultAndRespectsExplicitFlag(t *testing.T) {
	defaultPrompt := &textPromptStub{}
	got, err := prepareLoginArgs([]string{"login"}, defaultPrompt)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"login", "--username", "admin"}
	if !reflect.DeepEqual(got, want) || defaultPrompt.calls != 1 {
		t.Fatalf("args = %#v, prompt calls = %d", got, defaultPrompt.calls)
	}

	explicitPrompt := &textPromptStub{value: "ignored"}
	got, err = prepareLoginArgs([]string{"login", "--username", "operator"}, explicitPrompt)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"login", "--username", "operator"}
	if !reflect.DeepEqual(got, want) || explicitPrompt.calls != 0 {
		t.Fatalf("args = %#v, prompt calls = %d", got, explicitPrompt.calls)
	}
}

type loginCaptureService struct {
	*commandServiceStub
	username *string
}

func (s *loginCaptureService) Login(_ context.Context, username string) error {
	*s.username = username
	s.called = "login"
	return s.err
}

func TestReadCommandErrorsAndUsageHaveStableExitCodes(t *testing.T) {
	for _, test := range []struct {
		name     string
		args     []string
		service  *commandServiceStub
		wantExit int
	}{
		{"runtime error", []string{"info"}, &commandServiceStub{err: errors.New("router unavailable")}, 1},
		{"unknown command", []string{"unknown"}, &commandServiceStub{}, 2},
		{"missing api path", []string{"api", "get"}, &commandServiceStub{}, 2},
		{"password argument forbidden", []string{"login", "--password", "secret"}, &commandServiceStub{}, 2},
		{"wifi password argument forbidden", []string{"iot", "configure", "--password", "secret"}, &commandServiceStub{}, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := execute(context.Background(), test.args, test.service, &stdout, &stderr); got != test.wantExit {
				t.Fatalf("exit = %d, want %d", got, test.wantExit)
			}
			if test.wantExit != 0 && stderr.Len() == 0 {
				t.Fatal("stderr is empty")
			}
			if strings.Contains(stderr.String(), "secret") {
				t.Fatalf("stderr leaked argument: %q", stderr.String())
			}
		})
	}
}
