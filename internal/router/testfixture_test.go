package router

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nazar256/zyxelctl/internal/session"
)

type fixtureRouter struct {
	t                *testing.T
	server           *httptest.Server
	privateKey       *rsa.PrivateKey
	publicKeyPEM     string
	mu               sync.Mutex
	requests         []string
	loginCount       int
	protectedCount   int
	force401         bool
	malformed        bool
	invalidJSON      bool
	emptyGET         bool
	lastLogin        map[string]any
	lastCSRF         string
	lastCookie       string
	lastIfModified   string
	responseKey      []byte
	wlCheckDelay     time.Duration
	legacyPublicInfo []byte
	legacyStatusBody []byte
	rotateCSRF       bool
	identity         Identity
	loginFailure     string
}

func newFixtureRouter(t *testing.T) *fixtureRouter {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &fixtureRouter{
		t:            t,
		privateKey:   privateKey,
		publicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		identity:     Identity{Model: "EX5601-T1", Firmware: "V5.70(ACEA.0)T56C_b29"},
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "zyxelctl-fixture"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	fixture.server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER},
			PrivateKey:  privateKey,
		}},
	}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *fixtureRouter) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.lastIfModified = r.Header.Get("If-Modified-Since")
	switch r.URL.Path {
	case "/GetInfoNoLogin":
		if f.legacyPublicInfo != nil {
			_, _ = w.Write([]byte("<!doctype html><title>Configurator</title>"))
			return
		}
		writeJSON(w, map[string]any{"ModelName": "EX5601-T1", "CurrentLanguage": "en"})
	case "/getBasicInformation":
		if f.legacyPublicInfo == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(f.legacyPublicInfo)
	case "/getRSAPublickKey":
		writeJSON(w, map[string]any{"RSAPublicKey": f.publicKeyPEM})
	case "/UserLogin":
		f.loginCount++
		if f.loginFailure != "" {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"result": f.loginFailure, "secret": "must-not-leak-login-response"})
			return
		}
		var envelope Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			f.t.Errorf("decode login envelope: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		encryptedKey, err := decodeBase64(envelope.Key)
		if err != nil {
			f.t.Errorf("decode RSA key: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		transported, err := rsa.DecryptPKCS1v15(rand.Reader, f.privateKey, encryptedKey)
		if err != nil {
			f.t.Errorf("decrypt RSA key: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.responseKey, err = decodeBase64(string(transported))
		if err != nil {
			f.t.Errorf("decode transported AES key: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plaintext, err := DecryptEnvelope(envelope, f.responseKey)
		if err != nil {
			f.t.Errorf("decrypt login: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(plaintext, &f.lastLogin); err != nil {
			f.t.Errorf("decode login JSON: %v", err)
		}
		response, err := EncryptWithKey([]byte(`{"result":"ZCFG_SUCCESS","sessionkey":"fixture-csrf","loginLevel":"medium"}`), f.responseKey)
		if err != nil {
			f.t.Errorf("encrypt login response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "Session", Value: "fixture-cookie", Path: "/"})
		writeJSON(w, response)
	case "/cgi-bin/getBasicInformation":
		f.protectedCount++
		f.lastCookie = r.Header.Get("Cookie")
		if f.force401 || f.lastCookie == "" {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"result": "Invalid Username or Password"})
			return
		}
		if f.emptyGET {
			w.WriteHeader(http.StatusOK)
			return
		}
		if f.malformed {
			_, _ = w.Write([]byte("not-json"))
			return
		}
		plaintext, _ := json.Marshal(f.identity)
		if f.legacyPublicInfo != nil {
			plaintext = []byte("<!doctype html><title>Configurator</title>")
		}
		if f.invalidJSON {
			plaintext = []byte("not-json")
		}
		response, err := EncryptWithKey(plaintext, f.responseKey)
		if err != nil {
			f.t.Errorf("encrypt protected response: %v", err)
			return
		}
		writeJSON(w, response)
	case "/cgi-bin/DAL":
		f.lastCSRF = r.Header.Get("CSRFToken")
		f.lastCookie = r.Header.Get("Cookie")
		if r.URL.Query().Get("oid") == "status" {
			if f.force401 || f.lastCookie == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			plaintext, _ := json.Marshal(map[string]any{"result": "ZCFG_SUCCESS", "Object": []any{map[string]any{"DeviceInfo": f.identity}}})
			if f.legacyStatusBody != nil {
				plaintext = f.legacyStatusBody
			}
			response, err := EncryptWithKey(plaintext, f.responseKey)
			if err != nil {
				f.t.Errorf("encrypt protected status: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeJSON(w, response)
			return
		}
		if r.Method == http.MethodPut {
			if f.rotateCSRF {
				if f.lastCSRF != "fixture-csrf" && f.lastCSRF != "fixture-next-csrf" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if f.lastCSRF == "fixture-csrf" {
					response, _ := EncryptWithKey([]byte(`{"result":"ZCFG_SUCCESS","sessionkey":"fixture-next-csrf"}`), f.responseKey)
					writeJSON(w, response)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		response, err := EncryptWithKey([]byte(`{"result":"ZCFG_SUCCESS","Object":[]}`), f.responseKey)
		if err != nil {
			f.t.Errorf("encrypt DAL response: %v", err)
			return
		}
		writeJSON(w, response)
	case "/cgi-bin/Wireless":
		time.Sleep(f.wlCheckDelay)
		response, err := EncryptWithKey([]byte(`{"result":"ZCFG_SUCCESS"}`), f.responseKey)
		if err != nil {
			f.t.Errorf("encrypt WlCheck response: %v", err)
			return
		}
		writeJSON(w, response)
	case "/cgi-bin/Backup_Restore":
		_, _ = w.Write([]byte("fixture-binary-backup"))
	default:
		http.NotFound(w, r)
	}
}

func (f *fixtureRouter) countPath(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, request := range f.requests {
		if request == "GET "+path || request == "POST "+path || request == "PUT "+path {
			count++
		}
	}
	return count
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func decodeBase64(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

type promptStub struct {
	interactive bool
	confirm     bool
	password    string
	confirms    []string
	passwords   []string
}

func (p *promptStub) Interactive() bool { return p.interactive }
func (p *promptStub) Confirm(message string) (bool, error) {
	p.confirms = append(p.confirms, message)
	return p.confirm, nil
}
func (p *promptStub) Password(message string) (string, error) {
	p.passwords = append(p.passwords, message)
	return p.password, nil
}

func fixtureStore(t *testing.T, config session.Config, state *session.State) *session.Store {
	t.Helper()
	root := t.TempDir()
	paths := session.NewPaths(map[string]string{
		"XDG_CONFIG_HOME": root + "/config",
		"XDG_STATE_HOME":  root + "/state",
	}, root+"/home")
	store := session.NewStore(paths)
	if config.RouterURL != "" {
		if err := store.SaveConfig(config); err != nil {
			t.Fatal(err)
		}
	}
	if state != nil {
		if err := store.SaveState(*state); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func connectFixture(t *testing.T, fixture *fixtureRouter, store *session.Store, prompt Prompt, options LoginOptions) *Client {
	t.Helper()
	options.RouterURL = fixture.server.URL
	client, err := Connect(context.Background(), store, prompt, options)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
