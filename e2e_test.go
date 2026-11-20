//go:build linux

package zyxelctl_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	protocol "github.com/nazar256/zyxelctl/internal/router"
	"golang.org/x/sys/unix"
)

const (
	fixtureRouterPassword = "router-password-fixture"
	fixtureOldWiFi        = "old-password"
	fixtureNewWiFi        = "new-password"
	fixtureCSRF           = "fixture-csrf-token"
	fixtureCookie         = "fixture-cookie-value"
)

type e2eRouter struct {
	t              *testing.T
	server         *httptest.Server
	privateKey     *rsa.PrivateKey
	publicKeyPEM   string
	mu             sync.Mutex
	aesKey         []byte
	profiles       []map[string]any
	putCount       int
	failNext       bool
	sessionValid   bool
	identity       protocol.Identity
	legacyLogin    bool
	loginFailure   string
	loginCount     int
	guestNormalize bool
	guestFailAt    int
	guestPending   bool
}

func newE2ERouter(t *testing.T) *e2eRouter {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	router := &e2eRouter{
		t:            t,
		privateKey:   privateKey,
		publicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		identity:     protocol.Identity{Model: "EX5601-T1", Firmware: "V5.70(ACEA.0)T56C_b29"},
	}
	router.resetProfiles()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "zyxelctl-e2e"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	router.server = httptest.NewUnstartedServer(http.HandlerFunc(router.serveHTTP))
	router.server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER}, PrivateKey: privateKey,
		}},
	}
	router.server.StartTLS()
	t.Cleanup(router.server.Close)
	return router
}

func (r *e2eRouter) resetProfiles() {
	r.profiles = []map[string]any{
		{"Index": 1, "band": "2.4GHz", "wlEnable": true, "oneSsidEnable": true, "SSID": "Primary", "wlHide": false, "SecurityMode": "WPA2-Personal", "encryp": "aes", "AutoGenPSK": false, "PskDisplay": "primary-password", "RekeyingInterval": 3600, "IsolationEnable": false, "X_ZYXEL_BssIdIsolation": false},
		{"Index": 3, "band": "2.4GHz", "wlEnable": true, "oneSsidEnable": true, "SSID": "IoT-LAB", "wlHide": false, "SecurityMode": "WPA2-Personal", "encryp": "aes", "AutoGenPSK": false, "PskDisplay": fixtureOldWiFi, "RekeyingInterval": 3600, "IsolationEnable": false, "X_ZYXEL_BssIdIsolation": true, "FirmwareOnlyField": "preserve-me"},
		{"Index": 7, "band": "5GHz", "wlEnable": true, "oneSsidEnable": true, "SSID": "IoT-LAB", "wlHide": false, "SecurityMode": "WPA2-Personal", "encryp": "aes", "AutoGenPSK": false, "PskDisplay": fixtureOldWiFi, "RekeyingInterval": 3600, "IsolationEnable": false, "X_ZYXEL_BssIdIsolation": true, "FirmwareOnlyField": "preserve-me"},
	}
	r.putCount = 0
}

func (r *e2eRouter) serveHTTP(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch request.URL.Path {
	case "/":
		w.WriteHeader(http.StatusOK)
	case "/GetInfoNoLogin":
		if r.legacyLogin {
			_, _ = w.Write([]byte("<!doctype html><title>Configurator</title>"))
			return
		}
		writeFixtureJSON(w, map[string]any{"ModelName": "EX5601-T1", "CurrentLanguage": "en"})
	case "/getBasicInformation":
		writeFixtureJSON(w, map[string]any{"result": "ZCFG_SUCCESS", "ModelName": r.identity.Model, "SoftwareVersion": r.identity.Firmware, "CurrentLanguage": "en"})
	case "/getRSAPublickKey":
		writeFixtureJSON(w, map[string]any{"RSAPublicKey": r.publicKeyPEM})
	case "/UserLogin":
		r.handleLogin(w, request)
	case "/cgi-bin/getBasicInformation":
		if r.legacyLogin {
			r.writeProtected(w, "<!doctype html><title>Configurator</title>")
			return
		}
		r.writeProtected(w, r.identity)
	case "/cgi-bin/SteeringStatus_handle":
		r.writeProtected(w, []any{map[string]any{
			"mesh_value": true,
			"result_ctl": []any{map[string]any{"band": "5G", "bssid": "02:AA:BB:CC:DD:01", "ssid": "IoT-LAB", "status": "Up"}},
			"result_ext": []any{},
			"result_sta": []any{map[string]any{"station": "02:11:22:33:44:55", "bssid": "02:AA:BB:CC:DD:01", "ssid": "IoT-LAB", "band": "2.4G/5G", "stale": "NO", "PskDisplay": "must-not-leak"}},
		}})
	case "/cgi-bin/DAL":
		switch request.URL.Query().Get("oid") {
		case "status":
			r.writeProtected(w, map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"DeviceInfo": r.identity}}})
		case "wlan":
			if request.Method == http.MethodPut {
				r.handleWLANPut(w, request)
				return
			}
			r.writeProtected(w, map[string]any{"result": "ZCFG_SUCCESS", "Object": r.profiles})
		case "lan":
			r.writeProtected(w, map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"EnableDHCP": true}}})
		case "lanhosts":
			r.writeProtected(w, map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"lanhosts": []any{
				map[string]any{"Active": true, "IPAddress": "192.168.1.214", "DeviceName": "iot-laptop", "PhysAddress": "02:11:22:33:44:55", "InterfaceType": "Wi-Fi", "WiFiname": "IoT-Lab", "SupportedFrequencyBands": "5GHz", "X_ZYXEL_ConnectedAP": "Gateway", "PskDisplay": "must-not-leak"},
				map[string]any{"Active": false, "IPAddress": "192.168.1.215", "DeviceName": "offline-phone"},
			}}}})
		default:
			http.NotFound(w, request)
		}
	case "/cgi-bin/Wireless":
		r.guestPending = false
		r.writeProtected(w, map[string]any{"result": "ZCFG_SUCCESS"})
	case "/cgi-bin/Backup_Restore":
		_, _ = w.Write([]byte("fixture-router-configuration-backup"))
	default:
		http.NotFound(w, request)
	}
}

func (r *e2eRouter) handleLogin(w http.ResponseWriter, request *http.Request) {
	r.loginCount++
	if r.loginFailure != "" {
		w.WriteHeader(http.StatusUnauthorized)
		writeFixtureJSON(w, map[string]any{"result": r.loginFailure, "secret": "response-must-not-leak"})
		return
	}
	var envelope protocol.Envelope
	if err := json.NewDecoder(request.Body).Decode(&envelope); err != nil {
		r.t.Errorf("decode login envelope: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	encryptedKey, _ := base64.StdEncoding.DecodeString(envelope.Key)
	transported, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, encryptedKey)
	if err != nil {
		r.t.Errorf("decrypt login key: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.aesKey, err = base64.StdEncoding.DecodeString(string(transported))
	if err != nil {
		r.t.Errorf("decode login key: %v", err)
		return
	}
	plaintext, err := protocol.DecryptEnvelope(envelope, r.aesKey)
	if err != nil {
		r.t.Errorf("decrypt login payload: %v", err)
		return
	}
	var login map[string]any
	if err := json.Unmarshal(plaintext, &login); err != nil {
		r.t.Errorf("decode login payload: %v", err)
		return
	}
	wantPassword := base64.StdEncoding.EncodeToString([]byte(fixtureRouterPassword))
	if login["Input_Account"] != "admin" || login["Input_Passwd"] != wantPassword {
		r.t.Errorf("unexpected login fields")
		return
	}
	r.sessionValid = true
	http.SetCookie(w, &http.Cookie{Name: "Session", Value: fixtureCookie, Path: "/"})
	r.writeProtected(w, map[string]any{"result": "ZCFG_SUCCESS", "sessionkey": fixtureCSRF, "loginLevel": "medium"})
}

func (r *e2eRouter) handleWLANPut(w http.ResponseWriter, request *http.Request) {
	if !r.sessionValid || request.Header.Get("CSRFToken") != fixtureCSRF || !strings.Contains(request.Header.Get("Cookie"), fixtureCookie) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var envelope protocol.Envelope
	if err := json.NewDecoder(request.Body).Decode(&envelope); err != nil {
		r.t.Errorf("decode WLAN envelope: %v", err)
		return
	}
	plaintext, err := protocol.DecryptEnvelope(envelope, r.aesKey)
	if err != nil {
		r.t.Errorf("decrypt WLAN payload: %v", err)
		return
	}
	var updates []map[string]any
	if err := json.Unmarshal(plaintext, &updates); err != nil {
		if r.legacyLogin {
			var update map[string]any
			if err := json.Unmarshal(plaintext, &update); err == nil {
				r.handleGuestModePut(w, update)
				return
			}
		}
		r.t.Errorf("decode WLAN payload: %v", err)
		return
	}
	r.putCount++
	for _, update := range updates {
		if update["IsolationEnable"] == true && update["X_ZYXEL_BssIdIsolation"] == false {
			if _, isGuestModeUpdate := update["wlEnableGuest"]; isGuestModeUpdate {
				wantGuestFields := map[string]any{
					"div_wifiSubnet":  true,
					"wlSubnetState":   false,
					"subnetObjAction": nil,
					"MinAddress":      nil,
					"MaxAddress":      nil,
					"SubnetMask":      nil,
					"LANIP":           nil,
					"Interface":       nil,
				}
				for key, want := range wantGuestFields {
					if got, present := update[key]; !present || got != want {
						r.t.Errorf("peer-access field %s = %#v (present %t), want %#v", key, got, present, want)
					}
				}
			} else if len(update) != 3 {
				r.t.Errorf("narrow isolation probe contains %d fields, want exactly 3", len(update))
			}
		}
		index := int(update["Index"].(float64))
		for _, profile := range r.profiles {
			if int(profile["Index"].(int)) != index {
				continue
			}
			for key, value := range update {
				switch key {
				case "Index":
					// Identity selects the profile; it is not an updated field.
				case "psk_value":
					profile["PskDisplay"] = value
				case "securityLevel", "wpaMode", "wlEnableGuest", "wlGwMode":
				default:
					profile[key] = value
				}
			}
		}
	}
	if r.failNext && r.putCount == 1 {
		for _, profile := range r.profiles {
			if profile["Index"] == 3 {
				profile["SSID"] = "BROKEN"
			}
		}
	}
	r.sessionValid = false
	w.WriteHeader(http.StatusNoContent)
}

func (r *e2eRouter) handleGuestModePut(w http.ResponseWriter, update map[string]any) {
	r.putCount++
	if r.guestPending {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.guestFailAt == r.putCount {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	index, ok := update["Index"].(float64)
	mode, modeOK := update["wlGwMode"].(float64)
	if !ok || !modeOK || len(update) != 3 || update["wlEnableGuest"] != true || (index != 3 && index != 7) || (mode != 0 && mode != 1) {
		r.t.Errorf("invalid narrow guest-mode payload")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, profile := range r.profiles {
		if profile["Index"] == int(index) && !r.guestNormalize {
			profile["IsolationEnable"] = mode == 0
			profile["X_ZYXEL_BssIdIsolation"] = true
		}
	}
	r.guestPending = true
	w.WriteHeader(http.StatusNoContent)
}

func TestCLIExtenderIoTHomeGuest(t *testing.T) {
	extender := newE2ERouter(t)
	extender.identity = protocol.Identity{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b13"}
	extender.legacyLogin = true
	setExternal := func() {
		extender.mu.Lock()
		defer extender.mu.Unlock()
		extender.resetProfiles()
		for _, profile := range extender.profiles {
			if profile["Index"] == 3 || profile["Index"] == 7 {
				profile["SSID"] = "IoT-Lab"
				profile["MainSSID"] = false
				profile["IsolationEnable"] = true
			}
		}
		extender.guestNormalize, extender.guestFailAt = false, 0
		extender.guestPending = false
	}
	setExternal()
	root := t.TempDir()
	configRoot, stateRoot := filepath.Join(root, "config"), filepath.Join(root, "state")
	bin := filepath.Join(root, "zyxelctl")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", bin, "./cmd/zyxelctl")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	writePinnedConfigDirectory(t, filepath.Join(configRoot, "zyxelctl", "extender"), extender.server.URL, extender.server.Certificate().Raw)
	environment := append(os.Environ(), "XDG_CONFIG_HOME="+configRoot, "XDG_STATE_HOME="+stateRoot)
	if output, code := runPTYCommand(t, bin, environment, []string{"extender-login", "--username", "admin"}, []expectReply{{"Extender password:", fixtureRouterPassword + "\n"}}); code != 0 {
		t.Fatalf("login: %s", output)
	}
	args := []string{"--device", "extender", "iot", "home-guest", "--yes"}
	output, stderr, code := runCommand(t, bin, environment, args...)
	if code != 0 || !strings.Contains(output, `"changed": true`) || extender.putCount != 2 {
		t.Fatalf("home guest: exit=%d, output=%s, stderr=%s", code, output, stderr)
	}
	for _, profile := range extender.profiles {
		if profile["Index"] == 3 || profile["Index"] == 7 {
			if profile["IsolationEnable"] != false || profile["X_ZYXEL_BssIdIsolation"] != true || profile["SSID"] != "IoT-Lab" || profile["PskDisplay"] != fixtureOldWiFi {
				t.Fatal("IoT mode or preserved settings incorrect")
			}
		} else if profile["SSID"] != "Primary" {
			t.Fatal("non-target SSID changed")
		}
	}
	files, err := filepath.Glob(filepath.Join(stateRoot, "zyxelctl", "extender", "backups", "*", "iot-guest-mode.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("mode backup files: %v, %v", files, err)
	}
	assertMode(t, files[0], 0o600)
	backup, err := os.ReadFile(files[0])
	if err != nil || bytes.Contains(backup, []byte(fixtureOldWiFi)) || !bytes.Contains(backup, []byte(`"3": 0`)) {
		t.Fatalf("mode backup missing original mode or contains a passphrase: %v", err)
	}
	if output, stderr, code = runCommand(t, bin, environment, args...); code != 0 || !strings.Contains(output, `"changed": false`) || extender.putCount != 2 {
		t.Fatalf("repeat must be a no-op: %d, %s, %s", code, output, stderr)
	}
	for _, failure := range []string{"normalization", "partial failure"} {
		t.Run(failure, func(t *testing.T) {
			setExternal()
			extender.mu.Lock()
			if failure == "normalization" {
				extender.guestNormalize = true
			} else {
				extender.guestFailAt = 2
			}
			extender.mu.Unlock()
			_, stderr, code := runCommand(t, bin, environment, args...)
			if code != 1 || !strings.Contains(stderr, "rollback verified") || extender.putCount != 4 {
				t.Fatalf("failure did not roll back: exit=%d, puts=%d, stderr=%s", code, extender.putCount, stderr)
			}
			for _, profile := range extender.profiles {
				if profile["Index"] == 3 || profile["Index"] == 7 {
					if profile["IsolationEnable"] != true || profile["X_ZYXEL_BssIdIsolation"] != true {
						t.Fatal("original External Guest mode was not restored")
					}
				}
			}
		})
	}
	setExternal()
	_, stderr, code = runCommand(t, bin, environment, args[:len(args)-1]...)
	if code != 1 || !strings.Contains(stderr, "confirmation") || extender.putCount != 0 {
		t.Fatalf("noninteractive change lacked confirmation: exit=%d, stderr=%s", code, stderr)
	}
	extender.mu.Lock()
	extender.profiles[1]["IsolationEnable"] = false
	extender.mu.Unlock()
	output, stderr, code = runCommand(t, bin, environment, args...)
	if code != 0 || extender.putCount != 1 || !strings.Contains(output, `"changed": true`) {
		t.Fatalf("partial-state repair must update only the remaining profile: exit=%d, puts=%d, stderr=%s", code, extender.putCount, stderr)
	}
	setExternal()
	extender.mu.Lock()
	extender.profiles[1]["IsolationEnable"] = false
	extender.guestFailAt = 1
	extender.mu.Unlock()
	_, stderr, code = runCommand(t, bin, environment, args...)
	if code != 1 || extender.putCount != 2 || !strings.Contains(stderr, "rollback verified") {
		t.Fatalf("mixed-state rollback touched an unattempted profile: exit=%d, puts=%d, stderr=%s", code, extender.putCount, stderr)
	}
}

func (r *e2eRouter) writeProtected(w http.ResponseWriter, value any) {
	if !r.sessionValid || len(r.aesKey) != 32 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	plaintext, _ := json.Marshal(value)
	envelope, err := protocol.EncryptWithKey(plaintext, r.aesKey)
	if err != nil {
		r.t.Errorf("encrypt fixture response: %v", err)
		return
	}
	writeFixtureJSON(w, envelope)
}

func writeFixtureJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func TestCLIEndToEnd(t *testing.T) {
	router := newE2ERouter(t)
	root := t.TempDir()
	configRoot := filepath.Join(root, "config")
	stateRoot := filepath.Join(root, "state")
	bin := filepath.Join(root, "zyxelctl")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	build := exec.Command(goBinary, "build", "-o", bin, "./cmd/zyxelctl")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	writePinnedConfig(t, configRoot, router.server.URL, router.server.Certificate().Raw)
	environment := append(os.Environ(), "XDG_CONFIG_HOME="+configRoot, "XDG_STATE_HOME="+stateRoot, "GOTOOLCHAIN=local")
	var allOutput strings.Builder

	loginOutput, exit := runPTYCommand(t, bin, environment, []string{"login", "--username", "admin"}, []expectReply{{"Router password:", fixtureRouterPassword + "\n"}})
	allOutput.WriteString(loginOutput)
	if exit != 0 || !strings.Contains(loginOutput, `"authenticated": true`) {
		t.Fatalf("login exit = %d, output = %s", exit, loginOutput)
	}

	for _, args := range [][]string{{"session"}, {"info"}, {"status"}, {"wifi", "list"}, {"iot", "show"}} {
		stdout, stderr, code := runCommand(t, bin, environment, args...)
		allOutput.WriteString(stdout)
		allOutput.WriteString(stderr)
		if code != 0 || !json.Valid([]byte(stdout)) {
			t.Fatalf("%v exit = %d, stdout = %q, stderr = %q", args, code, stdout, stderr)
		}
	}
	clientsOut, clientsErr, code := runCommand(t, bin, environment, "clients", "list")
	allOutput.WriteString(clientsOut)
	allOutput.WriteString(clientsErr)
	if code != 0 || !json.Valid([]byte(clientsOut)) || !strings.Contains(clientsOut, "IoT-Lab") || strings.Contains(clientsOut, "offline-phone") || strings.Contains(clientsOut, "must-not-leak") {
		t.Fatalf("clients list exit = %d, stdout = %q, stderr = %q", code, clientsOut, clientsErr)
	}
	wifiClientsOut, wifiClientsErr, code := runCommand(t, bin, environment, "clients", "wifi")
	allOutput.WriteString(wifiClientsOut)
	allOutput.WriteString(wifiClientsErr)
	if code != 0 || !json.Valid([]byte(wifiClientsOut)) || !strings.Contains(wifiClientsOut, `"ssid": "IoT-LAB"`) || !strings.Contains(wifiClientsOut, `"band": "5GHz"`) || strings.Contains(wifiClientsOut, "must-not-leak") {
		t.Fatalf("clients wifi exit = %d, stdout = %q, stderr = %q", code, wifiClientsOut, wifiClientsErr)
	}

	backupOutput, backupError, code := runCommand(t, bin, environment, "config", "backup")
	allOutput.WriteString(backupOutput)
	allOutput.WriteString(backupError)
	if code != 0 {
		t.Fatalf("config backup exit = %d, stderr = %q", code, backupError)
	}
	assertBackupFileMode(t, stateRoot, "router.config", 0o600)

	configureOutput, exit := runPTYCommand(t, bin, environment, []string{"iot", "configure", "--ssid", "IoT-Lab", "--yes"}, []expectReply{
		{"Wi-Fi password:", fixtureNewWiFi + "\n"},
		{"Confirm Wi-Fi password:", fixtureNewWiFi + "\n"},
		{"Router password:", fixtureRouterPassword + "\n"},
	})
	allOutput.WriteString(configureOutput)
	if exit != 0 || !strings.Contains(configureOutput, `"changed": true`) {
		t.Fatalf("configure exit = %d, output = %s", exit, configureOutput)
	}
	router.mu.Lock()
	if router.putCount != 1 {
		router.mu.Unlock()
		t.Fatalf("configure PUT count = %d, want 1", router.putCount)
	}
	router.mu.Unlock()

	peerRequests := 0
	peerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		peerRequests++
		if request.Method != http.MethodHead {
			t.Errorf("peer request method = %s, want HEAD", request.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer peerServer.Close()
	probeOutput, exit := runPTYCommand(t, bin, environment, []string{"iot", "probe-isolation", "--target", peerServer.URL + "/", "--yes"}, []expectReply{
		{"Router password:", fixtureRouterPassword + "\n"},
		{"Router password:", fixtureRouterPassword + "\n"},
	})
	allOutput.WriteString(probeOutput)
	if exit != 0 || !strings.Contains(probeOutput, `"flags_retained": true`) || !strings.Contains(probeOutput, `"target_probed": true`) || !strings.Contains(probeOutput, `"target_reachable": true`) || !strings.Contains(probeOutput, `"rollback_verified": true`) || peerRequests != 1 {
		t.Fatalf("probe exit = %d, peer requests = %d, output = %q", exit, peerRequests, probeOutput)
	}
	router.mu.Lock()
	if router.putCount != 3 {
		router.mu.Unlock()
		t.Fatalf("cumulative probe PUT count = %d, want update and restore", router.putCount)
	}
	for _, profile := range router.profiles {
		index := profile["Index"].(int)
		if (index == 3 || index == 7) && (profile["IsolationEnable"] != false || profile["X_ZYXEL_BssIdIsolation"] != true) {
			router.mu.Unlock()
			t.Fatalf("probe did not restore profile %d", index)
		}
	}
	router.mu.Unlock()

	peerOutput, exit := runPTYCommand(t, bin, environment, []string{"iot", "allow-peers", "--yes"}, []expectReply{
		{"Router password:", fixtureRouterPassword + "\n"},
	})
	allOutput.WriteString(peerOutput)
	if exit != 0 || !strings.Contains(peerOutput, `"changed": true`) {
		t.Fatalf("allow-peers exit = %d, output = %q", exit, peerOutput)
	}
	router.mu.Lock()
	if router.putCount != 4 {
		router.mu.Unlock()
		t.Fatalf("cumulative peer-access PUT count = %d, want 4", router.putCount)
	}
	for _, profile := range router.profiles {
		index := profile["Index"].(int)
		if index != 3 && index != 7 {
			continue
		}
		if profile["IsolationEnable"] != true || profile["X_ZYXEL_BssIdIsolation"] != false || profile["SSID"] != "IoT-Lab" || profile["PskDisplay"] != fixtureNewWiFi {
			router.mu.Unlock()
			t.Fatalf("unsafe peer-access profile = %#v", profile)
		}
	}
	router.mu.Unlock()

	router.mu.Lock()
	router.resetProfiles()
	router.failNext = true
	router.mu.Unlock()
	failureOutput, exit := runPTYCommand(t, bin, environment, []string{"iot", "configure", "--ssid", "IoT-Lab", "--yes"}, []expectReply{
		{"Wi-Fi password:", fixtureNewWiFi + "\n"},
		{"Confirm Wi-Fi password:", fixtureNewWiFi + "\n"},
		{"Router password:", fixtureRouterPassword + "\n"},
		{"Router password:", fixtureRouterPassword + "\n"},
	})
	allOutput.WriteString(failureOutput)
	if exit != 1 || !strings.Contains(failureOutput, "rollback verified") {
		t.Fatalf("failure exit = %d, output = %s", exit, failureOutput)
	}
	router.mu.Lock()
	if router.putCount != 2 {
		router.mu.Unlock()
		t.Fatalf("failed configure PUT count = %d, want update plus rollback", router.putCount)
	}
	router.mu.Unlock()

	invalidOut, invalidErr, code := runCommand(t, bin, environment, "unknown")
	allOutput.WriteString(invalidOut)
	allOutput.WriteString(invalidErr)
	if code != 2 {
		t.Fatalf("invalid command exit = %d", code)
	}

	stateFile := filepath.Join(stateRoot, "zyxelctl", "session.json")
	assertMode(t, stateFile, 0o600)
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{fixtureRouterPassword, fixtureOldWiFi, fixtureNewWiFi} {
		if bytes.Contains(stateData, []byte(forbidden)) {
			t.Fatalf("session state contains password %q", forbidden)
		}
	}
	for _, forbidden := range []string{fixtureRouterPassword, fixtureOldWiFi, fixtureNewWiFi, fixtureCSRF, fixtureCookie} {
		if strings.Contains(allOutput.String(), forbidden) {
			t.Fatalf("captured CLI output contains secret %q", forbidden)
		}
	}

	_, logoutErr, code := runCommand(t, bin, environment, "logout")
	if code != 0 {
		t.Fatalf("logout exit = %d, stderr = %q", code, logoutErr)
	}
	sessionOut, sessionErr, code := runCommand(t, bin, environment, "session")
	if code != 0 || !strings.Contains(sessionOut, `"authenticated": false`) {
		t.Fatalf("post-logout session exit = %d, stdout = %q, stderr = %q", code, sessionOut, sessionErr)
	}
	if _, err := os.Stat(stateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session file still exists after logout: %v", err)
	}
}

func TestCLIRouterAndExtenderManagement(t *testing.T) {
	gateway, extender := newE2ERouter(t), newE2ERouter(t)
	extender.identity = protocol.Identity{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b13"}
	extender.legacyLogin = true
	root := t.TempDir()
	configRoot, stateRoot := filepath.Join(root, "config"), filepath.Join(root, "state")
	bin := filepath.Join(root, "zyxelctl")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", bin, "./cmd/zyxelctl")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	writePinnedConfig(t, configRoot, gateway.server.URL, gateway.server.Certificate().Raw)
	writePinnedConfigDirectory(t, filepath.Join(configRoot, "zyxelctl", "extender"), extender.server.URL, extender.server.Certificate().Raw)
	environment := append(os.Environ(), "XDG_CONFIG_HOME="+configRoot, "XDG_STATE_HOME="+stateRoot, "GOTOOLCHAIN=local")

	output, stderr, code := runCommand(t, bin, environment, "--device", "extender", "session")
	if code != 0 || !strings.Contains(output, `"authenticated": false`) {
		t.Fatalf("extender session selection: exit=%d, stderr=%s", code, stderr)
	}
	output, code = runPTYCommand(t, bin, environment, []string{"login", "--with-extender", "--username", "admin"}, []expectReply{{"Router and extender password:", fixtureRouterPassword + "\n"}})
	if code != 0 || strings.Count(output, "Router and extender password:") != 1 {
		t.Fatalf("combined login failed or prompted repeatedly: exit=%d, output=%s", code, output)
	}
	var captured strings.Builder
	captured.WriteString(output)
	for _, args := range [][]string{{"info"}, {"--device", "extender", "info"}, {"--device=extender", "wifi", "list"}} {
		out, errOut, exit := runCommand(t, bin, environment, args...)
		captured.WriteString(out)
		captured.WriteString(errOut)
		if exit != 0 || !json.Valid([]byte(out)) {
			t.Fatalf("%v: exit=%d, stderr=%s", args, exit, errOut)
		}
		if len(args) > 1 && args[len(args)-1] == "info" && !strings.Contains(out, "WX5600-T0") {
			t.Fatalf("extender info used the wrong target: %s", out)
		}
	}
	stateFiles := []string{filepath.Join(stateRoot, "zyxelctl", "session.json"), filepath.Join(stateRoot, "zyxelctl", "extender", "session.json")}
	var sessions [2]map[string]any
	for i, path := range stateFiles {
		assertMode(t, path, 0o600)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(fixtureRouterPassword)) {
			t.Fatal("combined login persisted the shared password")
		}
		if err := json.Unmarshal(data, &sessions[i]); err != nil {
			t.Fatal(err)
		}
	}
	if sessions[0]["aes_key"] == sessions[1]["aes_key"] || sessions[0]["model"] == sessions[1]["model"] {
		t.Fatal("router and extender sessions were not independent")
	}
	_, stderr, code = runCommand(t, bin, environment, "--device", "extender", "iot", "allow-peers", "--yes")
	if code != 2 || !strings.Contains(stderr, "read-only") || extender.putCount != 0 {
		t.Fatalf("extender unexpectedly accepted a router-only mutation: exit=%d, stderr=%s", code, stderr)
	}
	if _, stderr, code = runCommand(t, bin, environment, "--device", "extender", "logout"); code != 0 {
		t.Fatalf("extender logout: %s", stderr)
	}
	if _, stderr, code = runCommand(t, bin, environment, "--device", "extender", "info"); code != 1 || !strings.Contains(stderr, "zyxelctl extender-login") {
		t.Fatalf("extender authentication error suggested the wrong device login: exit=%d, stderr=%s", code, stderr)
	}
	if _, stderr, code = runCommand(t, bin, environment, "info"); code != 0 {
		t.Fatalf("extender logout damaged the router session: %s", stderr)
	}
	output, code = runPTYCommand(t, bin, environment, []string{"extender-login", "--url", extender.server.URL, "--username", "admin"}, []expectReply{{"Extender password:", fixtureRouterPassword + "\n"}})
	captured.WriteString(output)
	if code != 0 {
		t.Fatalf("native extender login alias failed: %s", output)
	}
	extender.mu.Lock()
	extender.loginFailure = "Locked User"
	beforeCount := extender.loginCount
	extender.mu.Unlock()
	output, code = runPTYCommand(t, bin, environment, []string{"login", "--with-extender", "--username", "admin"}, []expectReply{{"Router and extender password:", fixtureRouterPassword + "\n"}})
	captured.WriteString(output)
	var partial struct {
		Router struct {
			Authenticated bool `json:"authenticated"`
		} `json:"router"`
		Extender struct {
			Authenticated bool `json:"authenticated"`
		} `json:"extender"`
	}
	start := strings.Index(output, "{")
	if start < 0 {
		t.Fatalf("combined login did not emit a JSON result: %s", output)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output[start:])), &partial); err != nil {
		t.Fatal(err)
	}
	if code != 1 || !strings.Contains(output, "locked") || !partial.Router.Authenticated || partial.Extender.Authenticated {
		t.Fatalf("combined login did not report partial success safely: exit=%d, output=%s", code, output)
	}
	if extender.loginCount != beforeCount+1 {
		t.Fatal("failed extender authentication was retried")
	}
	if _, stderr, code = runCommand(t, bin, environment, "info"); code != 0 {
		t.Fatalf("extender login failure damaged the router session: %s", stderr)
	}
	gateway.mu.Lock()
	gateway.loginFailure = "Invalid Username or Password"
	gateway.mu.Unlock()
	beforeCount = extender.loginCount
	output, code = runPTYCommand(t, bin, environment, []string{"login", "--with-extender", "--username", "admin"}, []expectReply{{"Router and extender password:", fixtureRouterPassword + "\n"}})
	captured.WriteString(output)
	if code != 1 || !strings.Contains(output, `"skipped":true`) || extender.loginCount != beforeCount {
		t.Fatalf("failed router login sent credentials to the extender: exit=%d, output=%s", code, output)
	}
	for _, forbidden := range []string{fixtureRouterPassword, fixtureCSRF, fixtureCookie, "response-must-not-leak"} {
		if strings.Contains(captured.String(), forbidden) {
			t.Fatal("native device management disclosed authentication material")
		}
	}
}

type expectReply struct {
	expect string
	reply  string
}

func runPTYCommand(t *testing.T, binary string, environment []string, args []string, exchanges []expectReply) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = environment
	terminal, err := pty.Start(command)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	var output strings.Builder
	buffer := make([]byte, 512)
	for _, exchange := range exchanges {
		for !strings.Contains(output.String(), exchange.expect) {
			_ = terminal.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, readErr := terminal.Read(buffer)
			if n > 0 {
				output.Write(buffer[:n])
			}
			if readErr != nil {
				t.Fatalf("waiting for %q: %v; output=%q", exchange.expect, readErr, output.String())
			}
		}
		waitForEchoDisabled(t, terminal)
		if _, err := io.WriteString(terminal, exchange.reply); err != nil {
			t.Fatal(err)
		}
	}
	_ = terminal.SetReadDeadline(time.Time{})
	remaining, _ := io.ReadAll(terminal)
	output.Write(remaining)
	err = command.Wait()
	return output.String(), exitCode(err)
}

func waitForEchoDisabled(t *testing.T, terminal *os.File) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		state, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatalf("inspect terminal echo state: %v", err)
		}
		if state.Lflag&unix.ECHO == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal echo was not disabled after password prompt")
		}
		time.Sleep(time.Millisecond)
	}
}

func runCommand(t *testing.T, binary string, environment []string, args ...string) (string, string, int) {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), exitCode(err)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

func writePinnedConfig(t *testing.T, configRoot, routerURL string, certificate []byte) {
	t.Helper()
	writePinnedConfigDirectory(t, filepath.Join(configRoot, "zyxelctl"), routerURL, certificate)
}

func writePinnedConfigDirectory(t *testing.T, dir, routerURL string, certificate []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"router_url": routerURL, "username": "admin", "certificate_sha256": fingerprint(certificate),
	}
	data, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	text := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(text)/2)
	for i := 0; i < len(text); i += 2 {
		parts = append(parts, text[i:i+2])
	}
	return strings.Join(parts, ":")
}

func assertBackupFileMode(t *testing.T, stateRoot, name string, want os.FileMode) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(stateRoot, "zyxelctl", "backups", "*", name))
	if err != nil || len(matches) == 0 {
		t.Fatalf("backup %s not found: %v", name, err)
	}
	sort.Strings(matches)
	assertMode(t, matches[len(matches)-1], want)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}
