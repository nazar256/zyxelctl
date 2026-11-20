package router

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/nazar256/zyxelctl/internal/session"
)

const (
	DefaultRouterURL = "https://192.168.1.1"
	DefaultUsername  = "admin"
	wlanApplyTimeout = 90 * time.Second
)

type Prompt interface {
	Interactive() bool
	Confirm(message string) (bool, error)
	Password(message string) (string, error)
}

type Persistence interface {
	LoadConfig() (session.Config, error)
	SaveConfig(session.Config) error
	LoadState() (session.State, error)
	SaveState(session.State) error
	Logout() error
}

type LoginOptions struct {
	RouterURL          string
	Username           string
	ReplaceCertificate bool
	LoginCommand       string
	DeviceName         string
}

type Client struct {
	baseURL        *url.URL
	http           *http.Client
	store          Persistence
	prompt         Prompt
	config         session.Config
	state          session.State
	loginCommand   string
	legacyExtender bool
}

var ErrUnauthenticated = errors.New("router session is not authenticated")

type Identity struct {
	Model    string `json:"ModelName"`
	Firmware string `json:"SoftwareVersion"`
}

func Connect(ctx context.Context, store Persistence, prompt Prompt, options LoginOptions) (*Client, error) {
	config, err := store.LoadConfig()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load router configuration: %w", err)
	}
	if options.RouterURL != "" {
		config.RouterURL = options.RouterURL
	}
	if config.RouterURL == "" {
		config.RouterURL = DefaultRouterURL
	}
	if options.Username != "" {
		config.Username = options.Username
	}
	if config.Username == "" {
		config.Username = DefaultUsername
	}
	baseURL, err := url.Parse(config.RouterURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" {
		return nil, errors.New("router URL must be a valid https URL")
	}
	if baseURL.User != nil {
		return nil, errors.New("router URL must not contain user information")
	}
	fingerprint, err := inspectCertificate(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("inspect router certificate: %w", err)
	}
	if err := establishCertificateTrust(prompt, &config, fingerprint, baseURL.Host, options); err != nil {
		return nil, err
	}
	state, err := store.LoadState()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load router session: %w", err)
	}
	if err == nil && state.Peer != config {
		// An older session without a recorded peer cannot be verified either.
		if err := store.Logout(); err != nil {
			return nil, fmt.Errorf("clear unverified router session: %w", err)
		}
		state = session.State{}
	}
	if err := store.SaveConfig(config); err != nil {
		return nil, fmt.Errorf("save router configuration: %w", err)
	}
	transport := &http.Transport{
		Proxy: nil, // Router certificate inspection and API requests must take the same direct path.
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // Verified against the persisted leaf fingerprint below.
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("router presented no certificate")
				}
				if certificateFingerprint(state.PeerCertificates[0].Raw) != config.CertFingerprint {
					return errors.New("router certificate fingerprint changed")
				}
				return nil
			},
		},
	}
	client := &Client{
		baseURL: baseURL,
		http: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		store:        store,
		prompt:       prompt,
		config:       config,
		state:        state,
		loginCommand: options.LoginCommand,
	}
	client.legacyExtender = isLegacyExtender(Identity{Model: state.Model, Firmware: state.Firmware})
	return client, nil
}

func inspectCertificate(ctx context.Context, routerURL *url.URL) (string, error) {
	host := routerURL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	serverName := routerURL.Hostname()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: true, // Discovery only; no HTTP request or credential is sent.
	})
	if err != nil {
		return "", err
	}
	defer connection.Close()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	certificates := connection.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return "", errors.New("router presented no certificate")
	}
	return certificateFingerprint(certificates[0].Raw), nil
}

func establishCertificateTrust(prompt Prompt, config *session.Config, fingerprint, address string, options LoginOptions) error {
	if config.CertFingerprint == fingerprint {
		return nil
	}
	deviceName := options.DeviceName
	if deviceName == "" {
		deviceName = "router"
	}
	loginCommand := options.LoginCommand
	if loginCommand == "" {
		loginCommand = "zyxelctl login"
	}
	target := fmt.Sprintf("%s (%s)", deviceName, address)
	if config.CertFingerprint != "" && !options.ReplaceCertificate {
		return fmt.Errorf("%s certificate changed from %s to %s; run %s --replace-certificate to review it", target, config.CertFingerprint, fingerprint, loginCommand)
	}
	if prompt == nil || !prompt.Interactive() {
		return fmt.Errorf("%s certificate is not trusted and cannot be confirmed non-interactively", target)
	}
	message := fmt.Sprintf("Trust %s certificate SHA-256 %s?", target, fingerprint)
	if config.CertFingerprint != "" {
		message = fmt.Sprintf("Replace %s certificate SHA-256 %s with %s?", target, config.CertFingerprint, fingerprint)
	}
	confirmed, err := prompt.Confirm(message)
	if err != nil {
		return fmt.Errorf("confirm %s certificate: %w", target, err)
	}
	if !confirmed {
		return fmt.Errorf("%s certificate was not trusted", target)
	}
	config.CertFingerprint = fingerprint
	return nil
}

func certificateFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	hexValue := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(hexValue)/2)
	for i := 0; i < len(hexValue); i += 2 {
		parts = append(parts, hexValue[i:i+2])
	}
	return strings.Join(parts, ":")
}

func (c *Client) Get(ctx context.Context, path string, target any) error {
	if err := c.getProtectedJSON(ctx, path, target); err != nil {
		return err
	}
	return c.persistState()
}

// Identity validation must finish before a newly authenticated session is saved.
func (c *Client) getProtectedJSON(ctx context.Context, path string, target any) error {
	response, data, err := c.request(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("router returned an empty JSON response")
	}
	plaintext, err := c.decodeProtected(data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(plaintext, target); err != nil {
		return fmt.Errorf("%w: protected response is not valid JSON", ErrUnauthenticated)
	}
	if resultIsUnauthorized(target) {
		return ErrUnauthenticated
	}
	_ = response
	return nil
}

func (c *Client) Put(ctx context.Context, path string, payload any) error {
	return c.writeProtectedJSON(ctx, http.MethodPut, path, payload)
}

func (c *Client) Post(ctx context.Context, path string, payload any) error {
	return c.writeProtectedJSON(ctx, http.MethodPost, path, payload)
}

func (c *Client) Delete(ctx context.Context, path string, payload any) error {
	if _, err := c.sessionKey(); err != nil {
		return err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return errors.New("could not encode router deletion")
	}
	var parameters map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&parameters); err != nil || len(parameters) == 0 {
		return errors.New("router deletion requires nonempty scalar parameters")
	}
	reference, err := url.Parse(path)
	if err != nil {
		return errors.New("invalid router deletion path")
	}
	query := reference.Query()
	for name, value := range parameters {
		switch value.(type) {
		case string, bool, json.Number:
			query.Set(name, fmt.Sprint(value))
		default:
			return errors.New("router deletion requires scalar parameters")
		}
	}
	// The shipped UI places DELETE parameters in the URL, unlike POST/PUT
	// encrypted bodies. CSRF, pinned TLS and encrypted responses still apply.
	reference.RawQuery = query.Encode()
	_, data, err := c.request(ctx, http.MethodDelete, reference.String(), nil, true)
	if err != nil {
		return err
	}
	return c.finishProtectedWrite(data)
}

func (c *Client) writeProtectedJSON(ctx context.Context, method, path string, payload any) error {
	key, err := c.sessionKey()
	if err != nil {
		return err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return errors.New("could not encode router update")
	}
	envelope, err := EncryptWithKey(plaintext, key)
	if err != nil {
		return err
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return errors.New("could not encode encrypted router update")
	}
	_, data, err := c.request(ctx, method, path, body, true)
	if err != nil {
		return err
	}
	return c.finishProtectedWrite(data)
}

func (c *Client) finishProtectedWrite(data []byte) error {
	if len(data) > 0 {
		plaintext, err := c.decodeProtected(data)
		if err != nil {
			return err
		}
		var result map[string]any
		if err := json.Unmarshal(plaintext, &result); err != nil {
			return errors.New("router returned invalid update JSON")
		}
		if resultIsUnauthorized(result) {
			return ErrUnauthenticated
		}
		if text, ok := result["result"].(string); ok && text != "" && text != "ZCFG_SUCCESS" {
			return errors.New("router rejected update")
		}
	}
	return c.persistState()
}

func (c *Client) Download(ctx context.Context, path string) ([]byte, error) {
	_, data, err := c.request(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return nil, err
	}
	if err := c.persistState(); err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, mutating bool) (*http.Response, []byte, error) {
	reference, err := url.Parse(path)
	if err != nil {
		return nil, nil, errors.New("invalid router request path")
	}
	requestURL := c.baseURL.ResolveReference(reference)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return nil, nil, errors.New("could not create router request")
	}
	request.Header.Set("If-Modified-Since", "Thu, 01 Jun 1970 00:00:00 GMT")
	if body != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}
	if cookie := c.cookieHeader(); cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	if mutating {
		if c.state.CSRFToken == "" {
			return nil, nil, ErrUnauthenticated
		}
		request.Header.Set("CSRFToken", c.state.CSRFToken)
	}
	httpClient := c.http
	if reference.Path == "/cgi-bin/Wireless" && reference.Query().Get("action") == "WlCheck" && httpClient.Timeout > 0 && httpClient.Timeout < wlanApplyTimeout {
		extended := *httpClient
		extended.Timeout = wlanApplyTimeout
		httpClient = &extended
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("router request failed: %w", err)
	}
	defer response.Body.Close()
	c.updateCookies(response.Cookies())
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return response, nil, errors.New("could not read router response")
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return response, nil, ErrUnauthenticated
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response, nil, fmt.Errorf("router request returned HTTP %d", response.StatusCode)
	}
	return response, data, nil
}

func (c *Client) sessionKey() ([]byte, error) {
	if c.state.AESKey == "" {
		return nil, ErrUnauthenticated
	}
	key, err := base64.StdEncoding.DecodeString(c.state.AESKey)
	if err != nil || len(key) != 32 {
		return nil, ErrUnauthenticated
	}
	return key, nil
}

func (c *Client) decodeProtected(data []byte) ([]byte, error) {
	key, err := c.sessionKey()
	if err != nil {
		return nil, err
	}
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, errors.New("router returned invalid JSON")
	}
	if envelope.Content == "" || envelope.IV == "" {
		var result map[string]any
		if json.Unmarshal(data, &result) == nil && resultIsUnauthorized(result) {
			return nil, ErrUnauthenticated
		}
		return nil, errors.New("router returned an invalid encrypted response")
	}
	plaintext, err := DecryptEnvelope(envelope, key)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypted response could not be decrypted", ErrUnauthenticated)
	}
	// The firmware UI accepts refreshed session keys on protected responses.
	var refreshed struct {
		SessionKey string `json:"sessionkey"`
	}
	if json.Unmarshal(plaintext, &refreshed) == nil && refreshed.SessionKey != "" {
		c.state.CSRFToken = refreshed.SessionKey
	}
	return plaintext, nil
}

func (c *Client) updateCookies(cookies []*http.Cookie) {
	if c.state.Cookies == nil {
		c.state.Cookies = make(map[string]string)
	}
	for _, cookie := range cookies {
		if cookie.MaxAge < 0 {
			delete(c.state.Cookies, cookie.Name)
			continue
		}
		c.state.Cookies[cookie.Name] = cookie.Value
	}
}

func (c *Client) cookieHeader() string {
	keys := make([]string, 0, len(c.state.Cookies))
	for key := range c.state.Cookies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+c.state.Cookies[key])
	}
	return strings.Join(parts, "; ")
}

func (c *Client) persistState() error {
	if c.state.AESKey == "" {
		return nil
	}
	c.state.Peer = c.config
	if err := c.store.SaveState(c.state); err != nil {
		return fmt.Errorf("save router session: %w", err)
	}
	return nil
}

func resultIsUnauthorized(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	result, _ := object["result"].(string)
	return result == "Invalid Username or Password" || result == "ZCFG_REQUEST_REJECT"
}
