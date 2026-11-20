package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/session"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type writeRouter struct {
	before         []wifi.Profile
	after          []wifi.Profile
	afterRollback  []wifi.Profile
	identity       router.Identity
	identityAfter  router.Identity
	dhcpBefore     bool
	dhcpAfter      bool
	putCalls       int
	authCalls      int
	authErrors     map[int]error
	downloadCalls  int
	wlCheckCalls   int
	putPayloads    []any
	events         *[]string
	downloadErr    error
	putErrors      map[int]error
	wlCheckErrors  map[int]error
	retryAuth      bool
	authenticated  bool
	expireAfterPut bool
}

func (r *writeRouter) Authenticate(_ context.Context, operation func() error) error {
	r.authCalls++
	if err := r.authErrors[r.authCalls]; err != nil {
		return err
	}
	r.authenticated = true
	err := operation()
	if r.retryAuth && errors.Is(err, router.ErrUnauthenticated) {
		r.authenticated = true
		return operation()
	}
	return err
}
func (r *writeRouter) Login(context.Context, string) error { return nil }
func (r *writeRouter) ReadIdentity(ctx context.Context) (router.Identity, error) {
	var identity router.Identity
	err := r.Get(ctx, "/cgi-bin/getBasicInformation", &identity)
	return identity, err
}
func (r *writeRouter) Get(_ context.Context, path string, target any) error {
	if !r.authenticated {
		return router.ErrUnauthenticated
	}
	*r.events = append(*r.events, "get:"+path)
	var value any
	switch path {
	case "/cgi-bin/getBasicInformation":
		identity := r.identity
		if r.putCalls == 1 && r.identityAfter.Model != "" {
			identity = r.identityAfter
		}
		value = map[string]any{"ModelName": identity.Model, "SoftwareVersion": identity.Firmware}
	case "/cgi-bin/DAL?oid=wlan":
		profiles := r.before
		if r.putCalls == 1 {
			profiles = r.after
		} else if r.putCalls > 1 {
			profiles = r.afterRollback
		}
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": profiles}
	case "/cgi-bin/DAL?oid=lan":
		dhcp := r.dhcpBefore
		if r.putCalls == 1 {
			dhcp = r.dhcpAfter
		}
		value = map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"EnableDHCP": dhcp}}}
	case "/cgi-bin/Wireless?action=WlCheck":
		r.wlCheckCalls++
		if err := r.wlCheckErrors[r.wlCheckCalls]; err != nil {
			return err
		}
		value = map[string]any{"result": "ZCFG_SUCCESS"}
	default:
		return fmt.Errorf("unexpected GET %s", path)
	}
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, target)
}
func (r *writeRouter) Put(_ context.Context, path string, payload any) error {
	if !r.authenticated {
		return router.ErrUnauthenticated
	}
	*r.events = append(*r.events, "put:"+path)
	r.putCalls++
	r.putPayloads = append(r.putPayloads, payload)
	err := r.putErrors[r.putCalls]
	if r.expireAfterPut {
		r.authenticated = false
	}
	return err
}
func (r *writeRouter) Download(_ context.Context, path string) ([]byte, error) {
	*r.events = append(*r.events, "download:"+path)
	r.downloadCalls++
	if r.downloadErr != nil {
		return nil, r.downloadErr
	}
	return []byte("binary-router-backup"), nil
}

type backupStore struct {
	root        string
	events      *[]string
	files       map[string][]byte
	failFile    string
	createErr   error
	logoutCalls int
}

func (s *backupStore) LoadState() (session.State, error) { return session.State{}, os.ErrNotExist }
func (s *backupStore) Logout() error                     { s.logoutCalls++; return nil }
func (s *backupStore) CreateBackupDir(time.Time) (string, error) {
	*s.events = append(*s.events, "backup:create")
	if s.createErr != nil {
		return "", s.createErr
	}
	return s.root, nil
}
func (s *backupStore) WriteBackupFile(_ string, name string, data []byte) error {
	*s.events = append(*s.events, "backup:"+name)
	if name == s.failFile {
		return errors.New("injected backup write failure")
	}
	if s.files == nil {
		s.files = make(map[string][]byte)
	}
	s.files[name] = append([]byte(nil), data...)
	return nil
}

func writeProfiles() ([]wifi.Profile, []wifi.Profile) {
	before := []wifi.Profile{
		{Index: 1, WLEnable: true, SSID: "Primary", SecurityMode: "WPA2-Personal", Encryption: "aes", RekeyingInterval: 3600},
		{Index: 3, Band: "2.4GHz", WLEnable: true, OneSSIDEnable: true, SSID: "IoT-LAB", SecurityMode: "WPA2-Personal", Encryption: "aes", PskDisplay: "old-password", RekeyingInterval: 3600, BSSIDIsolation: true},
		{Index: 7, Band: "5GHz", WLEnable: true, OneSSIDEnable: true, SSID: "IoT-LAB", SecurityMode: "WPA2-Personal", Encryption: "aes", PskDisplay: "old-password", RekeyingInterval: 3600, BSSIDIsolation: true},
	}
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].SSID = "IoT-Lab"
			after[i].PskDisplay = "new-password"
		}
	}
	return before, after
}

func newWriteApp(t *testing.T) (*App, *writeRouter, *backupStore, *[]string) {
	t.Helper()
	before, after := writeProfiles()
	events := &[]string{}
	routerAPI := &writeRouter{
		before: before, after: after, afterRollback: before,
		identity:   router.Identity{Model: SupportedModel, Firmware: SupportedFirmware},
		dhcpBefore: true, dhcpAfter: true, events: events, authenticated: true,
	}
	store := &backupStore{root: filepath.Join(t.TempDir(), "backup"), events: events}
	output := Output{
		Interactive: true,
		Confirm:     func(string) (bool, error) { return true, nil },
		Password:    func(string) (string, error) { return "new-password", nil },
		Text:        func(_, fallback string) (string, error) { return fallback, nil },
		Now:         func() time.Time { return time.Date(2024, 1, 2, 9, 0, 0, 0, time.UTC) },
		Sleep:       func(time.Duration) {},
	}
	return New(routerAPI, store, output), routerAPI, store, events
}

func TestConfigureSuccessBacksUpBeforePutAndVerifiesState(t *testing.T) {
	application, routerAPI, store, events := newWriteApp(t)
	result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.BackupDirectory != store.root || result.RollbackAttempted {
		t.Fatalf("ConfigureIoT() = %#v", result)
	}
	if routerAPI.putCalls != 1 || routerAPI.wlCheckCalls != 1 {
		t.Fatalf("PUT calls = %d, WlCheck calls = %d", routerAPI.putCalls, routerAPI.wlCheckCalls)
	}
	wantFiles := []string{"manifest.json", "router.config", "wlan-profiles-3-7.json"}
	gotFiles := make([]string, 0, len(store.files))
	for name := range store.files {
		gotFiles = append(gotFiles, name)
	}
	slices.Sort(gotFiles)
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("backup files = %#v, want %#v", gotFiles, wantFiles)
	}
	putIndex := indexOf(*events, "put:/cgi-bin/DAL?oid=wlan")
	for _, backupEvent := range []string{"backup:router.config", "backup:wlan-profiles-3-7.json", "backup:manifest.json"} {
		if backupIndex := indexOf(*events, backupEvent); backupIndex < 0 || backupIndex > putIndex {
			t.Fatalf("events out of order: %#v", *events)
		}
	}
}

func TestConfigureHandlesSessionExpiryAfterPut(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	routerAPI.expireAfterPut = true
	routerAPI.retryAuth = true

	result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.RollbackAttempted {
		t.Fatalf("ConfigureIoT() = %#v", result)
	}
	if routerAPI.putCalls != 1 || routerAPI.authCalls < 2 {
		t.Fatalf("PUT calls = %d, authentication calls = %d", routerAPI.putCalls, routerAPI.authCalls)
	}
}

func TestConfigureRejectsUnsupportedIdentityBeforeBackupOrPut(t *testing.T) {
	application, routerAPI, store, _ := newWriteApp(t)
	routerAPI.identity.Firmware = "unexpected"
	_, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
	if err == nil || !strings.Contains(err.Error(), "unsupported router") {
		t.Fatalf("error = %v", err)
	}
	if routerAPI.putCalls != 0 || len(store.files) != 0 {
		t.Fatalf("put calls = %d, backup files = %d", routerAPI.putCalls, len(store.files))
	}
}

func TestConfigureRejectsProfileDriftBeforeBackupOrPut(t *testing.T) {
	application, routerAPI, store, _ := newWriteApp(t)
	routerAPI.before[2].SSID = "different"
	_, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
	if err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("error = %v", err)
	}
	if routerAPI.putCalls != 0 || len(store.files) != 0 {
		t.Fatalf("put calls = %d, backup files = %d", routerAPI.putCalls, len(store.files))
	}
}

func TestConfigureBackupFailurePreventsPut(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*writeRouter, *backupStore)
	}{
		{"create", func(_ *writeRouter, s *backupStore) { s.createErr = errors.New("create failed") }},
		{"download", func(r *writeRouter, _ *backupStore) { r.downloadErr = errors.New("download failed") }},
		{"router file", func(_ *writeRouter, s *backupStore) { s.failFile = "router.config" }},
		{"snapshot file", func(_ *writeRouter, s *backupStore) { s.failFile = "wlan-profiles-3-7.json" }},
		{"manifest file", func(_ *writeRouter, s *backupStore) { s.failFile = "manifest.json" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			application, routerAPI, store, _ := newWriteApp(t)
			test.configure(routerAPI, store)
			if _, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true); err == nil {
				t.Fatal("ConfigureIoT() error = nil")
			}
			if routerAPI.putCalls != 0 {
				t.Fatalf("PUT calls = %d, want 0", routerAPI.putCalls)
			}
		})
	}
}

func TestConfigBackupAndWiFiSnapshotWriteExpectedFiles(t *testing.T) {
	application, routerAPI, store, _ := newWriteApp(t)
	backup, err := application.ConfigBackup(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if backup.Directory != store.root || string(store.files["router.config"]) != "binary-router-backup" {
		t.Fatalf("ConfigBackup() = %#v, files = %#v", backup, store.files)
	}
	store.files = nil
	snapshot, err := application.WiFiSnapshot(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Directory != store.root || len(store.files["wlan-profiles-3-7.json"]) == 0 || routerAPI.putCalls != 0 {
		t.Fatalf("WiFiSnapshot() = %#v, files = %#v", snapshot, store.files)
	}
}

func TestRollbackRunsAfterEveryUncertainWriteFailure(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*writeRouter)
	}{
		{"PUT error", func(r *writeRouter) { r.putErrors = map[int]error{1: errors.New("injected PUT failure")} }},
		{"WlCheck error", func(r *writeRouter) { r.wlCheckErrors = map[int]error{1: errors.New("injected WlCheck failure")} }},
		{"target mismatch", func(r *writeRouter) { r.after[1].SSID = "wrong" }},
		{"non-target drift", func(r *writeRouter) { r.after[0].SSID = "changed-primary" }},
		{"DHCP drift", func(r *writeRouter) { r.dhcpAfter = false }},
		{"identity drift", func(r *writeRouter) { r.identityAfter = router.Identity{Model: SupportedModel, Firmware: "unexpected"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			application, routerAPI, _, _ := newWriteApp(t)
			test.configure(routerAPI)
			result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
			if err == nil {
				t.Fatal("ConfigureIoT() error = nil")
			}
			if !result.RollbackAttempted || !result.RollbackVerified {
				t.Fatalf("ConfigureIoT() result = %#v, error = %v", result, err)
			}
			if routerAPI.putCalls != 2 {
				t.Fatalf("PUT calls = %d, want update plus rollback", routerAPI.putCalls)
			}
			if !strings.Contains(err.Error(), "rollback verified") {
				t.Fatalf("error does not report rollback status: %v", err)
			}
		})
	}
}

func TestRollbackFailureIsReportedSeparately(t *testing.T) {
	t.Run("rollback PUT fails", func(t *testing.T) {
		application, routerAPI, _, _ := newWriteApp(t)
		routerAPI.after[1].SSID = "wrong"
		routerAPI.putErrors = map[int]error{2: errors.New("rollback PUT failed")}
		routerAPI.afterRollback = routerAPI.after // firmware did not apply the failed rollback
		result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
		if err == nil || !result.RollbackAttempted || result.RollbackVerified {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
		if !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(err.Error(), "verify updated IoT WLAN") {
			t.Fatalf("combined error = %v", err)
		}
	})

	t.Run("rollback verification fails", func(t *testing.T) {
		application, routerAPI, _, _ := newWriteApp(t)
		routerAPI.after[1].SSID = "wrong"
		routerAPI.afterRollback = routerAPI.after
		result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
		if err == nil || !result.RollbackAttempted || result.RollbackVerified {
			t.Fatalf("result = %#v, error = %v", result, err)
		}
		if !strings.Contains(err.Error(), "rollback verification failed") {
			t.Fatalf("combined error = %v", err)
		}
	})
}

func TestConfigurePostWriteErrorDoesNotRetryRollbackPut(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	routerAPI.after[1].SSID = "wrong"
	routerAPI.putErrors = map[int]error{2: router.ErrUnauthenticated}
	routerAPI.afterRollback = routerAPI.after // firmware did not apply the failed rollback
	routerAPI.retryAuth = true

	result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
	if err == nil || !result.RollbackAttempted || result.RollbackVerified {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if routerAPI.putCalls != 2 {
		t.Fatalf("PUT calls = %d, want one update and one rollback attempt", routerAPI.putCalls)
	}
	if !strings.Contains(err.Error(), "rollback failed") || errors.Is(err, router.ErrUnauthenticated) {
		t.Fatalf("post-write error remains retryable: %v", err)
	}
}

func TestRollbackResponseCanFailAfterFirmwareRestoresProfiles(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	routerAPI.after[1].SSID = "wrong"
	routerAPI.putErrors = map[int]error{2: router.ErrUnauthenticated}
	routerAPI.expireAfterPut = true
	routerAPI.retryAuth = true

	result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
	if err == nil || !result.RollbackAttempted || !result.RollbackVerified {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if routerAPI.putCalls != 2 || !strings.Contains(err.Error(), "rollback verified") || errors.Is(err, router.ErrUnauthenticated) {
		t.Fatalf("uncertain rollback was replayed or misreported: PUT calls = %d, error = %v", routerAPI.putCalls, err)
	}
}

func TestConfigurePostWriteErrorIsTerminalAfterVerifiedRollback(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	routerAPI.putErrors = map[int]error{1: router.ErrUnauthenticated}
	routerAPI.retryAuth = true

	result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true)
	if err == nil || !result.RollbackAttempted || !result.RollbackVerified {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if routerAPI.putCalls != 2 {
		t.Fatalf("PUT calls = %d, want one uncertain update and one rollback", routerAPI.putCalls)
	}
	if errors.Is(err, router.ErrUnauthenticated) || !strings.Contains(err.Error(), "rollback verified") {
		t.Fatalf("post-write error remains retryable: %v", err)
	}
}

func TestConfigureConfirmationOccursOnceAndCancellationDoesNotWrite(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	confirmCalls := 0
	application.output.Confirm = func(string) (bool, error) {
		confirmCalls++
		return false, nil
	}
	routerAPI.retryAuth = true

	result, err := application.ConfigureIoT(context.Background(), "IoT-Lab", false)
	if err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if confirmCalls != 1 || routerAPI.putCalls != 0 {
		t.Fatalf("confirmation calls = %d, PUT calls = %d", confirmCalls, routerAPI.putCalls)
	}
}

func TestConfigurePromptsForDefaultSSIDAndMatchingPassword(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	textCalls := 0
	passwords := []string{"new-password", "new-password"}
	passwordCalls := 0
	application.output.Text = func(message, fallback string) (string, error) {
		textCalls++
		if fallback != "" || !strings.Contains(message, "Network name") {
			t.Fatalf("SSID prompt = %q fallback %q", message, fallback)
		}
		return "IoT-Lab", nil
	}
	application.output.Password = func(string) (string, error) {
		value := passwords[passwordCalls]
		passwordCalls++
		return value, nil
	}
	if _, err := application.ConfigureIoT(context.Background(), "", true); err != nil {
		t.Fatal(err)
	}
	if textCalls != 1 || passwordCalls != 2 || routerAPI.putCalls != 1 {
		t.Fatalf("text calls = %d, password calls = %d, PUT calls = %d", textCalls, passwordCalls, routerAPI.putCalls)
	}
}

func TestConfigureRejectsMismatchedPasswordBeforeRouterWrite(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	passwords := []string{"first-password", "other-password"}
	calls := 0
	application.output.Password = func(string) (string, error) {
		value := passwords[calls]
		calls++
		return value, nil
	}
	if _, err := application.ConfigureIoT(context.Background(), "IoT-Lab", true); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("error = %v", err)
	}
	if routerAPI.putCalls != 0 || routerAPI.downloadCalls != 0 {
		t.Fatalf("PUT calls = %d, download calls = %d", routerAPI.putCalls, routerAPI.downloadCalls)
	}
}

func TestEnableIoTPeerAccessBacksUpBeforeSwappingFlags(t *testing.T) {
	application, routerAPI, store, events := newWriteApp(t)
	before, _ := writeProfiles()
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].IsolationEnable = true
			after[i].BSSIDIsolation = false
		}
	}
	routerAPI.before = before
	routerAPI.after = after
	routerAPI.afterRollback = before

	result, err := application.EnableIoTPeerAccess(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.BackupDirectory != store.root || result.RollbackAttempted {
		t.Fatalf("EnableIoTPeerAccess() = %#v", result)
	}
	if routerAPI.putCalls != 1 || routerAPI.wlCheckCalls != 1 {
		t.Fatalf("PUT calls = %d, WlCheck calls = %d", routerAPI.putCalls, routerAPI.wlCheckCalls)
	}
	payload, ok := routerAPI.putPayloads[0].([]map[string]any)
	if !ok || len(payload) != 2 {
		t.Fatalf("payload = %#v", routerAPI.putPayloads[0])
	}
	for _, profile := range payload {
		if profile["IsolationEnable"] != true || profile["X_ZYXEL_BssIdIsolation"] != false || profile["SSID"] != "IoT-LAB" || profile["psk_value"] != "old-password" {
			t.Fatalf("unsafe peer-access payload = %#v", profile)
		}
	}
	putIndex := indexOf(*events, "put:/cgi-bin/DAL?oid=wlan")
	for _, backupEvent := range []string{"backup:router.config", "backup:wlan-profiles-3-7.json", "backup:manifest.json"} {
		if backupIndex := indexOf(*events, backupEvent); backupIndex < 0 || backupIndex > putIndex {
			t.Fatalf("events out of order: %#v", *events)
		}
	}
}

func TestEnableIoTPeerAccessHandlesSessionExpiryAfterPut(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	before, _ := writeProfiles()
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].IsolationEnable = true
			after[i].BSSIDIsolation = false
		}
	}
	routerAPI.before = before
	routerAPI.after = after
	routerAPI.afterRollback = before
	routerAPI.expireAfterPut = true
	routerAPI.retryAuth = true

	result, err := application.EnableIoTPeerAccess(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.RollbackAttempted {
		t.Fatalf("EnableIoTPeerAccess() = %#v", result)
	}
	if routerAPI.putCalls != 1 || routerAPI.authCalls < 2 {
		t.Fatalf("PUT calls = %d, authentication calls = %d", routerAPI.putCalls, routerAPI.authCalls)
	}
}

func TestEnableIoTPeerAccessRejectsUnexpectedOrientationBeforeBackupOrWrite(t *testing.T) {
	application, routerAPI, store, _ := newWriteApp(t)
	for i := range routerAPI.before {
		if routerAPI.before[i].Index == 3 || routerAPI.before[i].Index == 7 {
			routerAPI.before[i].IsolationEnable = true
			routerAPI.before[i].BSSIDIsolation = false
		}
	}
	if _, err := application.EnableIoTPeerAccess(context.Background(), true); err == nil {
		t.Fatal("EnableIoTPeerAccess() error = nil")
	}
	if routerAPI.putCalls != 0 || len(store.files) != 0 {
		t.Fatalf("PUT calls = %d, backup files = %d", routerAPI.putCalls, len(store.files))
	}
}

func TestEnableIoTPeerAccessRollsBackVerificationFailure(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	before, _ := writeProfiles()
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].IsolationEnable = true
			after[i].BSSIDIsolation = false
		}
	}
	after[1].SSID = "unexpected"
	routerAPI.before = before
	routerAPI.after = after
	routerAPI.afterRollback = before

	result, err := application.EnableIoTPeerAccess(context.Background(), true)
	if err == nil || !result.RollbackAttempted || !result.RollbackVerified {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if routerAPI.putCalls != 2 || !strings.Contains(err.Error(), "rollback verified") {
		t.Fatalf("PUT calls = %d, error = %v", routerAPI.putCalls, err)
	}
}

func TestEnableIoTPeerAccessRollbackSessionExpiryDoesNotRepeatEitherPut(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	before, _ := writeProfiles()
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].IsolationEnable = true
			after[i].BSSIDIsolation = false
		}
	}
	after[1].SSID = "unexpected"
	routerAPI.before = before
	routerAPI.after = after
	routerAPI.afterRollback = before
	routerAPI.expireAfterPut = true
	routerAPI.retryAuth = true

	result, err := application.EnableIoTPeerAccess(context.Background(), true)
	if err == nil || !result.RollbackAttempted || !result.RollbackVerified {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if routerAPI.putCalls != 2 {
		t.Fatalf("PUT calls = %d, want one update and one rollback", routerAPI.putCalls)
	}
	if errors.Is(err, router.ErrUnauthenticated) || !strings.Contains(err.Error(), "rollback verified") {
		t.Fatalf("post-write error remains retryable: %v", err)
	}
}

func TestWiFiRestoreValidatesSnapshotBacksUpAndVerifies(t *testing.T) {
	application, routerAPI, store, _ := newWriteApp(t)
	original, configured := writeProfiles()
	routerAPI.before = configured
	routerAPI.after = original
	routerAPI.afterRollback = configured
	targets := []wifi.Profile{original[1], original[2]}
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := application.WiFiRestore(context.Background(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.BackupDirectory != store.root || routerAPI.putCalls != 1 {
		t.Fatalf("result = %#v, PUT calls = %d", result, routerAPI.putCalls)
	}
}

func TestWiFiRestoreHandlesSessionExpiryAfterPut(t *testing.T) {
	application, routerAPI, store, _ := newWriteApp(t)
	original, configured := writeProfiles()
	routerAPI.before = configured
	routerAPI.after = original
	routerAPI.afterRollback = configured
	routerAPI.expireAfterPut = true
	routerAPI.retryAuth = true
	targets := []wifi.Profile{original[1], original[2]}
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := application.WiFiRestore(context.Background(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.BackupDirectory != store.root || result.RollbackAttempted {
		t.Fatalf("WiFiRestore() = %#v", result)
	}
	if routerAPI.putCalls != 1 || routerAPI.authCalls < 2 {
		t.Fatalf("PUT calls = %d, authentication calls = %d", routerAPI.putCalls, routerAPI.authCalls)
	}
}

func TestWiFiRestoreRejectsMalformedSnapshotBeforeBackupOrPut(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`[{"Index":3}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := application.WiFiRestore(context.Background(), path, true); err == nil {
		t.Fatal("WiFiRestore() error = nil")
	}
	if routerAPI.putCalls != 0 || routerAPI.downloadCalls != 0 {
		t.Fatalf("PUT calls = %d, download calls = %d", routerAPI.putCalls, routerAPI.downloadCalls)
	}
}

func TestProbeIoTIsolationRestoresAfterReachabilityCheck(t *testing.T) {
	application, routerAPI, store, events := newWriteApp(t)
	before, _ := writeProfiles()
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].IsolationEnable = true
			after[i].BSSIDIsolation = false
		}
	}
	routerAPI.before, routerAPI.after, routerAPI.afterRollback = before, after, before
	application.output.Probe = func(_ context.Context, target string) (int, error) {
		*events = append(*events, "probe")
		if target != "http://192.168.1.214:9876/" || routerAPI.putCalls != 1 {
			t.Fatalf("probe target = %q, PUT calls = %d", target, routerAPI.putCalls)
		}
		return 200, nil
	}

	result, err := application.ProbeIoTIsolation(context.Background(), "http://192.168.1.214:9876/", true)
	if err != nil {
		t.Fatal(err)
	}
	if result.BackupDirectory != store.root || !result.FlagsRetained || !result.TargetProbed || !result.TargetReachable || result.HTTPStatus != 200 || !result.RollbackVerified {
		t.Fatalf("ProbeIoTIsolation() = %#v", result)
	}
	if routerAPI.putCalls != 2 || routerAPI.wlCheckCalls != 2 {
		t.Fatalf("PUT calls = %d, WlCheck calls = %d", routerAPI.putCalls, routerAPI.wlCheckCalls)
	}
	first, ok := routerAPI.putPayloads[0].([]map[string]any)
	if !ok || !reflect.DeepEqual(first, []map[string]any{
		{"Index": 3, "IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false},
		{"Index": 7, "IsolationEnable": true, "X_ZYXEL_BssIdIsolation": false},
	}) {
		t.Fatalf("probe payload = %#v", routerAPI.putPayloads[0])
	}
	if indexOf(*events, "backup:manifest.json") > indexOf(*events, "put:/cgi-bin/DAL?oid=wlan") ||
		indexOf(*events, "probe") < indexOf(*events, "put:/cgi-bin/DAL?oid=wlan") {
		t.Fatalf("unsafe event order: %#v", *events)
	}
}

func TestProbeIoTIsolationTreatsIgnoredFlagsAsNoChange(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	before, _ := writeProfiles()
	routerAPI.before, routerAPI.after, routerAPI.afterRollback = before, before, before
	application.output.Probe = func(context.Context, string) (int, error) {
		t.Fatal("network probe ran although the router ignored the flag change")
		return 0, nil
	}

	result, err := application.ProbeIoTIsolation(context.Background(), "http://192.168.1.214:9876/", true)
	if err != nil {
		t.Fatal(err)
	}
	if result.FlagsRetained || result.TargetProbed || result.TargetReachable || !result.RollbackVerified {
		t.Fatalf("ProbeIoTIsolation() = %#v", result)
	}
	if routerAPI.putCalls != 1 {
		t.Fatalf("PUT calls = %d, want only the ignored narrow update", routerAPI.putCalls)
	}
}

func TestProbeIoTIsolationRejectsUnsafeTargetBeforeBackup(t *testing.T) {
	application, routerAPI, store, _ := newWriteApp(t)
	if _, err := application.ProbeIoTIsolation(context.Background(), "https://example.com/", true); err == nil {
		t.Fatal("ProbeIoTIsolation() error = nil")
	}
	if routerAPI.putCalls != 0 || routerAPI.downloadCalls != 0 || len(store.files) != 0 {
		t.Fatalf("PUT calls = %d, downloads = %d, backup files = %d", routerAPI.putCalls, routerAPI.downloadCalls, len(store.files))
	}
}

func TestProbeIoTIsolationDoesNotRestoreWhenAuthenticationFailsBeforeWrite(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	routerAPI.authErrors = map[int]error{2: errors.New("authentication failed")}
	if _, err := application.ProbeIoTIsolation(context.Background(), "http://192.168.1.214:9876/", true); err == nil {
		t.Fatal("ProbeIoTIsolation() error = nil")
	}
	if routerAPI.putCalls != 0 {
		t.Fatalf("PUT calls = %d, want no probe or restore write", routerAPI.putCalls)
	}
}

func TestProbeIoTIsolationRestoresWhenTargetIsUnreachable(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	before, _ := writeProfiles()
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].IsolationEnable = true
			after[i].BSSIDIsolation = false
		}
	}
	routerAPI.before, routerAPI.after, routerAPI.afterRollback = before, after, before
	application.output.Probe = func(context.Context, string) (int, error) {
		return 0, errors.New("connection refused")
	}
	result, err := application.ProbeIoTIsolation(context.Background(), "http://192.168.1.214:9876/", true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.FlagsRetained || !result.TargetProbed || result.TargetReachable || result.ProbeError == "" || !result.RollbackVerified || routerAPI.putCalls != 2 {
		t.Fatalf("result = %#v, PUT calls = %d", result, routerAPI.putCalls)
	}
}

func TestProbeIoTIsolationReportsFailedRestore(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	before, _ := writeProfiles()
	after := append([]wifi.Profile(nil), before...)
	for i := range after {
		if after[i].Index == 3 || after[i].Index == 7 {
			after[i].IsolationEnable = true
			after[i].BSSIDIsolation = false
		}
	}
	routerAPI.before, routerAPI.after, routerAPI.afterRollback = before, after, after
	application.output.Probe = func(context.Context, string) (int, error) { return 200, nil }
	result, err := application.ProbeIoTIsolation(context.Background(), "http://192.168.1.214:9876/", true)
	if err == nil || !strings.Contains(err.Error(), "manual recovery") || result.RollbackVerified || routerAPI.putCalls != 2 {
		t.Fatalf("result = %#v, error = %v, PUT calls = %d", result, err, routerAPI.putCalls)
	}
}

func TestProbeIoTIsolationRestoresAfterUncertainPut(t *testing.T) {
	application, routerAPI, _, _ := newWriteApp(t)
	before, _ := writeProfiles()
	routerAPI.before, routerAPI.after, routerAPI.afterRollback = before, before, before
	routerAPI.putErrors = map[int]error{1: errors.New("uncertain PUT")}
	result, err := application.ProbeIoTIsolation(context.Background(), "http://192.168.1.214:9876/", true)
	if err == nil || !result.RollbackVerified || routerAPI.putCalls != 2 {
		t.Fatalf("result = %#v, error = %v, PUT calls = %d", result, err, routerAPI.putCalls)
	}
}

func indexOf(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}
