package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nazar256/zyxelctl/internal/session"
)

func TestCertificateFirstUseRequiresConfirmationBeforeHTTP(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	prompt := &promptStub{interactive: true, confirm: true}
	client := connectFixture(t, fixture, store, prompt, LoginOptions{})
	if client == nil {
		t.Fatal("Connect() returned nil client")
	}
	if len(prompt.confirms) != 1 || !strings.Contains(prompt.confirms[0], "SHA-256") {
		t.Fatalf("certificate confirmations = %#v", prompt.confirms)
	}
	if len(fixture.requests) != 0 {
		t.Fatalf("HTTP requests before certificate trust = %#v", fixture.requests)
	}
	config, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.CertFingerprint == "" {
		t.Fatal("certificate fingerprint was not persisted")
	}
	if config.RouterURL != fixture.server.URL || config.Username != "admin" {
		t.Fatalf("saved config = %#v", config)
	}
}

func TestCertificatePinnedReuseDoesNotPrompt(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	firstPrompt := &promptStub{interactive: true, confirm: true}
	connectFixture(t, fixture, store, firstPrompt, LoginOptions{})
	secondPrompt := &promptStub{interactive: false}
	connectFixture(t, fixture, store, secondPrompt, LoginOptions{})
	if len(secondPrompt.confirms) != 0 {
		t.Fatalf("pinned reuse prompted: %#v", secondPrompt.confirms)
	}
}

func TestRouterRequestsNeverUseAmbientProxy(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP transport type = %T", client.http.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("router HTTP transport must not use an ambient proxy")
	}
}

func TestRouterRequestsRejectRedirects(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	if client.http.CheckRedirect == nil || client.http.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		t.Fatal("router HTTP client must stop at the original response")
	}
}

func TestRouterURLRejectsUserInfoBeforeConnecting(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	address := strings.Replace(fixture.server.URL, "https://", "https://fixture-user@", 1)
	_, err := Connect(context.Background(), store, nil, LoginOptions{RouterURL: address})
	if err == nil || err.Error() != "router URL must not contain user information" {
		t.Fatalf("expected router URL user information to be rejected before connecting, got %v", err)
	}
}

func TestCertificateChangeRefusedBeforeLogin(t *testing.T) {
	first := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	connectFixture(t, first, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	second := newFixtureRouter(t)
	config, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.RouterURL = second.server.URL
	if err := store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	_, err = Connect(context.Background(), store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("Connect() error = %v, want certificate error", err)
	}
	if second.loginCount != 0 {
		t.Fatalf("login count = %d, credentials may have been sent", second.loginCount)
	}
}

func TestCertificateChangeCanBeConfirmedForReplacement(t *testing.T) {
	first := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	connectFixture(t, first, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	oldConfig, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	second := newFixtureRouter(t)
	oldConfig.RouterURL = second.server.URL
	if err := store.SaveConfig(oldConfig); err != nil {
		t.Fatal(err)
	}
	prompt := &promptStub{interactive: true, confirm: true}
	connectFixture(t, second, store, prompt, LoginOptions{ReplaceCertificate: true})
	newConfig, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if newConfig.CertFingerprint == oldConfig.CertFingerprint {
		t.Fatal("certificate fingerprint was not replaced")
	}
	if len(prompt.confirms) != 1 || !strings.Contains(prompt.confirms[0], oldConfig.CertFingerprint) {
		t.Fatalf("replacement confirmation = %#v", prompt.confirms)
	}
}

func TestCertificateReplacementClearsCachedSession(t *testing.T) {
	first := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	previous := connectFixture(t, first, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	if err := store.SaveState(session.State{Peer: previous.config, CSRFToken: "fixture-token", Cookies: map[string]string{"session": "fixture-cookie"}}); err != nil {
		t.Fatal(err)
	}
	second := newFixtureRouter(t)
	prompt := &promptStub{interactive: true, confirm: true}
	client := connectFixture(t, second, store, prompt, LoginOptions{ReplaceCertificate: true})
	if client.state.CSRFToken != "" || len(client.state.Cookies) != 0 {
		t.Fatal("replacement reused cached session state")
	}
	client = connectFixture(t, second, store, &promptStub{}, LoginOptions{})
	if client.state.CSRFToken != "" || len(client.state.Cookies) != 0 {
		t.Fatal("replacement left previous session state on disk")
	}
}

func TestUnboundCachedSessionRequiresFreshLogin(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	if err := store.SaveState(session.State{CSRFToken: "fixture-token", Cookies: map[string]string{"session": "fixture-cookie"}}); err != nil {
		t.Fatal(err)
	}
	client := connectFixture(t, fixture, store, &promptStub{}, LoginOptions{})
	if client.state.CSRFToken != "" || len(client.state.Cookies) != 0 {
		t.Fatal("session without a recorded peer was reused")
	}
}

func TestExtenderCertificateTrustIdentifiesTarget(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	options := LoginOptions{DeviceName: "extender", LoginCommand: "zyxelctl extender-login"}
	prompt := &promptStub{interactive: true, confirm: true}
	connectFixture(t, fixture, store, prompt, options)
	if len(prompt.confirms) != 1 || !strings.Contains(prompt.confirms[0], "Trust extender (") || !strings.Contains(prompt.confirms[0], fixture.server.Listener.Addr().String()) {
		t.Fatalf("extender trust confirmation = %#v", prompt.confirms)
	}
	config, err := store.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	config.CertFingerprint = "OLD-PIN"
	if err := store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	prompt = &promptStub{interactive: true, confirm: true}
	options.RouterURL = fixture.server.URL
	_, err = Connect(context.Background(), store, prompt, options)
	if err == nil || !strings.Contains(err.Error(), "extender (") || !strings.Contains(err.Error(), "run zyxelctl extender-login --replace-certificate") {
		t.Fatalf("extender certificate mismatch error = %v", err)
	}
	if len(prompt.confirms) != 0 || len(prompt.passwords) != 0 || len(fixture.requests) != 0 {
		t.Fatal("changed certificate prompted or sent HTTP before explicit replacement")
	}
	options.ReplaceCertificate = true
	connectFixture(t, fixture, store, prompt, options)
	if len(prompt.confirms) != 1 || !strings.Contains(prompt.confirms[0], "Replace extender (") || !strings.Contains(prompt.confirms[0], "OLD-PIN") {
		t.Fatalf("extender replacement confirmation = %#v", prompt.confirms)
	}
}

func TestLoginUsesEncryptedNormalFlowAndPersistsSession(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	prompt := &promptStub{interactive: true, confirm: true, password: "router-password-fixture"}
	client := connectFixture(t, fixture, store, prompt, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	wantLogin := map[string]any{
		"Input_Account":    "admin",
		"Input_Passwd":     base64.StdEncoding.EncodeToString([]byte("router-password-fixture")),
		"currLang":         "en",
		"RememberPassword": float64(0),
		"SHA512_password":  false,
	}
	if !reflect.DeepEqual(fixture.lastLogin, wantLogin) {
		t.Fatalf("login payload = %#v, want %#v", fixture.lastLogin, wantLogin)
	}
	if len(prompt.passwords) != 1 {
		t.Fatalf("password prompts = %d, want 1", len(prompt.passwords))
	}
	state, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if state.AESKey == "" || state.CSRFToken != "fixture-csrf" || state.Cookies["Session"] != "fixture-cookie" {
		t.Fatalf("persisted state = %#v", state)
	}
	if state.Model != "EX5601-T1" || state.Firmware != "V5.70(ACEA.0)T56C_b29" {
		t.Fatalf("persisted identity = %s %s", state.Model, state.Firmware)
	}
	stored, err := os.ReadFile(store.Paths.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "router-password-fixture") {
		t.Fatal("router password persisted in session state")
	}
	if fixture.countPath("/getBasicInformation") != 0 {
		t.Fatal("normal login unexpectedly used the legacy public endpoint")
	}
}

func TestLoginLegacyExtenderPublicInformation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		wantLogin bool
	}{
		{"supported extender", `{"result":"ZCFG_SUCCESS","ModelName":"WX5600-T0","SoftwareVersion":"V5.70(ACDW.0)b13","CurrentLanguage":"nl"}`, true},
		{"unsupported model", `{"result":"ZCFG_SUCCESS","ModelName":"other","SoftwareVersion":"V5.70(ACDW.0)b13"}`, false},
		{"unsupported firmware", `{"result":"ZCFG_SUCCESS","ModelName":"WX5600-T0","SoftwareVersion":"other"}`, false},
		{"rejected response", `{"result":"ZCFG_REQUEST_REJECT","ModelName":"WX5600-T0","SoftwareVersion":"V5.70(ACDW.0)b13"}`, false},
		{"missing identity", `{}`, false},
		{"malformed response", `not-json`, false},
		{"empty response", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newFixtureRouter(t)
			fixture.legacyPublicInfo = []byte(tc.body)
			fixture.identity = Identity{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b13"}
			store := fixtureStore(t, session.Config{}, nil)
			client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "fixture-extender-password"}, LoginOptions{})
			err := client.Login(context.Background(), "admin")
			if !tc.wantLogin {
				if err == nil || fixture.loginCount != 0 {
					t.Fatalf("invalid public information allowed credentials to be sent: error=%v, logins=%d", err, fixture.loginCount)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if fixture.lastLogin["currLang"] != "nl" || fixture.loginCount != 1 {
				t.Fatalf("legacy login did not preserve language or exactly-once submission")
			}
			state, err := store.LoadState()
			if err != nil || state.Model != fixture.identity.Model || state.Firmware != fixture.identity.Firmware {
				t.Fatalf("legacy session identity did not match the authenticated response: %v", err)
			}
		})
	}
}

func TestLoginFailureReportsOnlyKnownSafeReasons(t *testing.T) {
	for _, tc := range []struct{ result, want string }{
		{"Invalid Username or Password", "username or password"},
		{"Locked User", "locked"},
		{"Duplicated login", "duplicate"},
		{"Maxium number of login account has reached", "session limit"},
		{"HTTP permission denied", "permission denied"},
		{"A user exist", "duplicate"},
		{"Invalid Verifying Code", "verification code"},
		{"untrusted-result-must-not-leak", "HTTP 401"},
	} {
		t.Run(tc.result, func(t *testing.T) {
			fixture := newFixtureRouter(t)
			fixture.loginFailure = tc.result
			store := fixtureStore(t, session.Config{}, nil)
			client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "fixture-password-must-not-leak"}, LoginOptions{})
			err := client.Login(context.Background(), "admin")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("login error = %v, want safe reason %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "must-not-leak") || fixture.loginCount != 1 {
				t.Fatal("login response leaked or authentication was retried")
			}
		})
	}
}

func TestLegacyExtenderSessionUsesProtectedStatus(t *testing.T) {
	fixture := newFixtureRouter(t)
	fixture.identity = Identity{Model: "WX5600-T0", Firmware: "V5.70(ACDW.0)b13"}
	fixture.legacyPublicInfo = []byte(`{"result":"ZCFG_SUCCESS","ModelName":"WX5600-T0","SoftwareVersion":"V5.70(ACDW.0)b13"}`)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "fixture-extender-password"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatalf("legacy extender login: %v", err)
	}
	// A new process must recover the protocol from its validated saved identity.
	client = connectFixture(t, fixture, store, &promptStub{}, LoginOptions{})
	identity, err := client.ValidateSession(context.Background())
	if err != nil || identity.Model != "WX5600-T0" || identity.Firmware != "V5.70(ACDW.0)b13" {
		t.Fatalf("cached legacy session: identity=%#v error=%v", identity, err)
	}
	if fixture.countPath("/cgi-bin/getBasicInformation") != 0 || fixture.countPath("/cgi-bin/DAL?oid=status") != 2 || fixture.loginCount != 1 {
		t.Fatalf("legacy validation used the wrong endpoint or reauthenticated: %#v", fixture.requests)
	}
	fixture.force401 = true
	if _, err := client.ValidateSession(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("public identity allowed an expired session: %v", err)
	}
}

func TestProtectedWriteRefreshesSessionToken(t *testing.T) {
	fixture := newFixtureRouter(t)
	fixture.rotateCSRF = true
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "fixture-password"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if err := client.Put(context.Background(), "/cgi-bin/DAL?oid=wlan", map[string]any{"Index": 3}); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadState()
	if err != nil || state.CSRFToken != "fixture-next-csrf" {
		t.Fatal("refreshed write token was not saved")
	}
	if err := client.Put(context.Background(), "/cgi-bin/DAL?oid=wlan", map[string]any{"Index": 7}); err != nil {
		t.Fatal(err)
	}
	if fixture.lastCSRF != "fixture-next-csrf" {
		t.Fatal("next write used the old token")
	}
}

func TestProtectedWriteFailureKeepsUnverifiedResultPrivate(t *testing.T) {
	key := make([]byte, 32)
	client := &Client{state: session.State{AESKey: base64.StdEncoding.EncodeToString(key)}}
	envelope, err := EncryptWithKey([]byte(`{"result":"fixture-device-message"}`), key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.finishProtectedWrite(data); err == nil || err.Error() != "router rejected update" {
		t.Fatal("protected write failure must report a fixed error message")
	}
}

func TestReservationCreateUsesEncryptedBodyAndDeleteUsesQuery(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "fixture-password"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	var methods []string
	fixture.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cgi-bin/DAL" || r.URL.Query().Get("oid") != "static_dhcp" {
			fixture.serveHTTP(w, r)
			return
		}
		methods = append(methods, r.Method)
		if r.Header.Get("CSRFToken") != "fixture-csrf" || r.Header.Get("Cookie") == "" {
			t.Error("mutation missing authentication")
		}
		if r.Method == http.MethodDelete {
			body, _ := io.ReadAll(r.Body)
			if len(body) != 0 || r.URL.Query().Get("Index") != "133" || r.Header.Get("Content-Type") != "" {
				t.Error("DELETE must carry Index in the query and have no body")
			}
			response, _ := EncryptWithKey([]byte(`{"result":"ZCFG_SUCCESS"}`), fixture.responseKey)
			writeJSON(w, response)
			return
		}
		var envelope Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		plaintext, err := DecryptEnvelope(envelope, fixture.responseKey)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(plaintext, &payload); err != nil || payload["Index"] != float64(133) {
			t.Errorf("unexpected payload: %s", plaintext)
		}
		response, _ := EncryptWithKey([]byte(`{"result":"ZCFG_SUCCESS"}`), fixture.responseKey)
		writeJSON(w, response)
	})
	if err := client.Delete(context.Background(), "/cgi-bin/DAL?oid=static_dhcp", map[string]any{"Index": 133}); err != nil {
		t.Fatal(err)
	}
	if err := client.Post(context.Background(), "/cgi-bin/DAL?oid=static_dhcp", map[string]any{"Index": 133}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(methods, []string{"DELETE", "POST"}) {
		t.Fatalf("mutation methods: %v", methods)
	}
}

func TestDeleteEncodesScalarQueryParametersAndRejectsNestedPayloads(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "fixture-password"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	fixture.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodDelete || r.URL.Query().Get("oid") != "static_dhcp" || r.URL.Query().Get("Label") != "a&b=c" || r.URL.Query().Get("Enable") != "false" {
			t.Error("DELETE query encoding changed parameter values")
		}
		response, _ := EncryptWithKey([]byte(`{"result":"ZCFG_SUCCESS"}`), fixture.responseKey)
		writeJSON(w, response)
	})
	if err := client.Delete(context.Background(), "/cgi-bin/DAL?oid=static_dhcp", map[string]any{"Label": "a&b=c", "Enable": false}); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []any{map[string]any{"Index": []int{1}}, map[string]any{"Index": nil}, []int{1}, nil} {
		if err := client.Delete(context.Background(), "/cgi-bin/DAL?oid=static_dhcp", payload); err == nil {
			t.Fatalf("unsupported payload accepted: %#v", payload)
		}
	}
	if calls != 1 {
		t.Fatalf("unsafe payload caused a request: %d", calls)
	}
}

func TestLegacyExtenderRejectsUnverifiedStatusWithoutSavingSession(t *testing.T) {
	for _, body := range []string{
		`not-json`,
		`{"result":"ZCFG_REQUEST_REJECT"}`,
		`{"result":"ZCFG_SUCCESS","Object":[]}`,
		`{"Object":[{"DeviceInfo":{"ModelName":"WX5600-T0","SoftwareVersion":"V5.70(ACDW.0)b13"}}]}`,
		`{"result":"ZCFG_SUCCESS","Object":[{"DeviceInfo":{"ModelName":"WX5600-T0"}}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			fixture := newFixtureRouter(t)
			fixture.legacyPublicInfo = []byte(`{"result":"ZCFG_SUCCESS","ModelName":"WX5600-T0","SoftwareVersion":"V5.70(ACDW.0)b13"}`)
			fixture.legacyStatusBody = []byte(body)
			store := fixtureStore(t, session.Config{}, nil)
			client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "fixture-extender-password"}, LoginOptions{})
			if err := client.Login(context.Background(), "admin"); err == nil {
				t.Fatal("unverified protected status accepted as a session")
			}
			if _, err := store.LoadState(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unverified session was saved: %v", err)
			}
		})
	}
}

func TestRequestUsesCookiesCSRFAndDecryptsResponses(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "password-123"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := client.Get(context.Background(), "/cgi-bin/DAL?oid=wlan", &value); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{}}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("GET value = %#v, want %#v", value, want)
	}
	if err := client.Put(context.Background(), "/cgi-bin/DAL?oid=wlan", map[string]any{"SSID": "IoT-Lab"}); err != nil {
		t.Fatal(err)
	}
	if fixture.lastCookie != "Session=fixture-cookie" {
		t.Fatalf("Cookie = %q", fixture.lastCookie)
	}
	if fixture.lastCSRF != "fixture-csrf" {
		t.Fatalf("CSRFToken = %q", fixture.lastCSRF)
	}
	if fixture.lastIfModified != "Thu, 01 Jun 1970 00:00:00 GMT" {
		t.Fatalf("If-Modified-Since = %q", fixture.lastIfModified)
	}
}

func TestWlCheckUsesFirmwareApplyTimeout(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "password-123"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	client.http.Timeout = 10 * time.Millisecond
	fixture.wlCheckDelay = 50 * time.Millisecond

	var value map[string]any
	if err := client.Get(context.Background(), "/cgi-bin/Wireless?action=WlCheck", &value); err != nil {
		t.Fatalf("WlCheck used the ordinary request timeout: %v", err)
	}
	if value["result"] != "ZCFG_SUCCESS" {
		t.Fatalf("WlCheck response = %#v", value)
	}
}

func TestRequestRejectsMalformedAndEmptyGETWithoutLeakingBody(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "password-123"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	fixture.malformed = true
	var value map[string]any
	err := client.Get(context.Background(), "/cgi-bin/getBasicInformation", &value)
	if err == nil || strings.Contains(err.Error(), "not-json") {
		t.Fatalf("malformed GET error = %v", err)
	}
	fixture.malformed = false
	fixture.emptyGET = true
	err = client.Get(context.Background(), "/cgi-bin/getBasicInformation", &value)
	if err == nil {
		t.Fatal("empty GET accepted")
	}
}

func TestInvalidDecryptedProtectedJSONIsUnauthenticated(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "password-123"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	fixture.invalidJSON = true

	var identity Identity
	err := client.Get(context.Background(), "/cgi-bin/getBasicInformation", &identity)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Get() error = %v, want ErrUnauthenticated", err)
	}
}

func TestSessionCachedReuseDoesNotRelogin(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	first := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "password-123"}, LoginOptions{})
	if err := first.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	second := connectFixture(t, fixture, store, &promptStub{interactive: false}, LoginOptions{})
	identity, err := second.ValidateSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Model != "EX5601-T1" || fixture.loginCount != 1 {
		t.Fatalf("identity = %#v, login count = %d", identity, fixture.loginCount)
	}
}

func TestAuthenticationReloginsStaleSessionAndRetriesOperationOnce(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	first := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	stale := session.State{
		Peer:      first.config,
		AESKey:    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		CSRFToken: "stale-token",
		Cookies:   map[string]string{},
	}
	if err := store.SaveState(stale); err != nil {
		t.Fatal(err)
	}
	prompt := &promptStub{interactive: true, confirm: true, password: "password-123"}
	client := connectFixture(t, fixture, store, prompt, LoginOptions{})
	calls := 0
	err := client.WithAuthentication(context.Background(), func(client *Client) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || fixture.loginCount != 1 {
		t.Fatalf("operation calls = %d, login count = %d", calls, fixture.loginCount)
	}
}

func TestAuthenticationRetriesOperationOnlyOnceAfterUnauthorized(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	prompt := &promptStub{interactive: true, confirm: true, password: "password-123"}
	client := connectFixture(t, fixture, store, prompt, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := client.WithAuthentication(context.Background(), func(client *Client) error {
		calls++
		return ErrUnauthenticated
	})
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error = %v, want ErrUnauthenticated", err)
	}
	if calls != 2 || fixture.loginCount != 2 {
		t.Fatalf("operation calls = %d, login count = %d", calls, fixture.loginCount)
	}
}

func TestAuthenticationReloginsAfterDecryptionFailure(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	firstPrompt := &promptStub{interactive: true, confirm: true, password: "password-123"}
	first := connectFixture(t, fixture, store, firstPrompt, LoginOptions{})
	if err := first.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	state.AESKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if err := store.SaveState(state); err != nil {
		t.Fatal(err)
	}
	second := connectFixture(t, fixture, store, &promptStub{interactive: true, password: "password-123"}, LoginOptions{})
	if err := second.WithAuthentication(context.Background(), func(*Client) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if fixture.loginCount != 2 {
		t.Fatalf("login count = %d, want 2", fixture.loginCount)
	}
}

func TestAuthenticationNonInteractiveStaleSessionFails(t *testing.T) {
	fixture := newFixtureRouter(t)
	stale := &session.State{AESKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	store := fixtureStore(t, session.Config{}, nil)
	connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true}, LoginOptions{})
	if err := store.SaveState(*stale); err != nil {
		t.Fatal(err)
	}
	client := connectFixture(t, fixture, store, &promptStub{interactive: false}, LoginOptions{})
	calls := 0
	err := client.WithAuthentication(context.Background(), func(*Client) error {
		calls++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "zyxelctl login") {
		t.Fatalf("error = %v, want login instruction", err)
	}
	if calls != 0 || fixture.loginCount != 0 {
		t.Fatalf("operation calls = %d, login count = %d", calls, fixture.loginCount)
	}
}

func TestRequestDownloadReturnsBinaryBackup(t *testing.T) {
	fixture := newFixtureRouter(t)
	store := fixtureStore(t, session.Config{}, nil)
	client := connectFixture(t, fixture, store, &promptStub{interactive: true, confirm: true, password: "password-123"}, LoginOptions{})
	if err := client.Login(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	data, err := client.Download(context.Background(), "/cgi-bin/Backup_Restore?action=Backup")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "fixture-binary-backup" {
		t.Fatalf("backup = %q", data)
	}
}
