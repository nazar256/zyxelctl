package router

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func (c *Client) Login(ctx context.Context, username string) error {
	if c.prompt == nil || !c.prompt.Interactive() {
		return c.loginRequired("interactive terminal required")
	}
	password, err := c.prompt.Password("Router password: ")
	if err != nil {
		return fmt.Errorf("read router password: %w", err)
	}
	return c.LoginWithPassword(ctx, username, password)
}

// LoginWithPassword authenticates once using a credential already entered by
// the user. It permits a combined device login without persisting the password
// or sharing certificate pins, cookies, CSRF tokens, or AES session keys.
func (c *Client) LoginWithPassword(ctx context.Context, username, password string) error {
	if username == "" {
		username = DefaultUsername
	}
	if password == "" {
		return errors.New("router password must not be empty")
	}
	legacyExtender := false

	// The browser UI performs this request first; its response may establish a
	// cookie on real firmware. A non-success status is intentionally ignored.
	_, _, _ = c.requestWithoutSession(ctx, http.MethodGet, "/", nil)

	var noLogin struct {
		CurrentLanguage string `json:"CurrentLanguage"`
	}
	if err := c.getPlainJSON(ctx, "/GetInfoNoLogin", &noLogin); err != nil {
		// The WX5600 b13 login UI uses this older public endpoint. Keep
		// the fallback limited to the identity whose protocol was verified.
		var legacy struct {
			Identity
			Result          string `json:"result"`
			CurrentLanguage string `json:"CurrentLanguage"`
		}
		if legacyErr := c.getPlainJSON(ctx, "/getBasicInformation", &legacy); legacyErr != nil ||
			legacy.Result != "ZCFG_SUCCESS" || !isLegacyExtender(legacy.Identity) {
			return err
		}
		legacyExtender = true
		noLogin.CurrentLanguage = legacy.CurrentLanguage
	}
	if noLogin.CurrentLanguage == "" {
		noLogin.CurrentLanguage = "en"
	}
	var keyInfo struct {
		RSAPublicKey string `json:"RSAPublicKey"`
	}
	if err := c.getPlainJSON(ctx, "/getRSAPublickKey", &keyInfo); err != nil {
		return fmt.Errorf("read login public key: %w", err)
	}
	if keyInfo.RSAPublicKey == "" {
		return errors.New("router returned no login public key")
	}
	payload := map[string]any{
		"Input_Account":    username,
		"Input_Passwd":     base64.StdEncoding.EncodeToString([]byte(password)),
		"currLang":         noLogin.CurrentLanguage,
		"RememberPassword": 0,
		"SHA512_password":  false,
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return errors.New("could not encode login request")
	}
	envelope, aesKey, err := EncryptEnvelope(plaintext, []byte(keyInfo.RSAPublicKey))
	if err != nil {
		return fmt.Errorf("prepare encrypted login: %w", err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return errors.New("could not encode encrypted login")
	}
	response, data, err := c.requestWithoutSession(ctx, http.MethodPost, "/UserLogin", body)
	if err != nil {
		return loginRequestError(data, err)
	}
	c.updateCookies(response.Cookies())
	var responseEnvelope Envelope
	if err := json.Unmarshal(data, &responseEnvelope); err != nil {
		return errors.New("router returned invalid login JSON")
	}
	decrypted, err := DecryptEnvelope(responseEnvelope, aesKey)
	if err != nil {
		return errors.New("router returned an invalid encrypted login response")
	}
	var login struct {
		Result     string `json:"result"`
		SessionKey string `json:"sessionkey"`
	}
	if err := json.Unmarshal(decrypted, &login); err != nil {
		return errors.New("router returned invalid login data")
	}
	if login.Result != "ZCFG_SUCCESS" || login.SessionKey == "" {
		return errors.New("router login failed")
	}
	c.state.AESKey = base64.StdEncoding.EncodeToString(aesKey)
	c.state.CSRFToken = login.SessionKey
	c.state.LoggedInAt = time.Now().UTC()
	c.config.Username = username
	c.legacyExtender = legacyExtender
	identity, err := c.ValidateSession(ctx)
	if err != nil {
		return fmt.Errorf("validate new router session: %w", err)
	}
	c.state.Model = identity.Model
	c.state.Firmware = identity.Firmware
	if err := c.store.SaveConfig(c.config); err != nil {
		return fmt.Errorf("save router username: %w", err)
	}
	return c.persistState()
}

func loginRequestError(data []byte, requestErr error) error {
	var result struct {
		Result string `json:"result"`
	}
	if json.Unmarshal(data, &result) == nil {
		// Only these fixed messages may leave the HTTP client. Responses may
		// contain credentials or arbitrary device-supplied strings.
		switch result.Result {
		case "Invalid Username or Password":
			return errors.New("router rejected username or password")
		case "Locked User":
			return errors.New("router account is locked; wait before retrying")
		case "Duplicated login", "A user exist":
			return errors.New("router rejected a duplicate administrator login")
		case "Maxium number of login account has reached":
			return errors.New("router administrator session limit reached")
		case "HTTP permission denied":
			return errors.New("router login permission denied")
		case "Invalid Verifying Code":
			return errors.New("router rejected the verification code; use its normal login interface")
		}
	}
	return fmt.Errorf("submit encrypted login: %w", requestErr)
}

func (c *Client) ValidateSession(ctx context.Context) (Identity, error) {
	identity, err := c.ReadIdentity(ctx)
	if err != nil {
		return Identity{}, err
	}
	c.state.Model = identity.Model
	c.state.Firmware = identity.Firmware
	c.state.LastValidatedAt = time.Now().UTC()
	if err := c.persistState(); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func isLegacyExtender(identity Identity) bool {
	return identity.Model == "WX5600-T0" && identity.Firmware == "V5.70(ACDW.0)b13"
}

// ReadIdentity uses a protected endpoint for both supported device protocols.
// The older extender's public basic information is not session validation.
func (c *Client) ReadIdentity(ctx context.Context) (Identity, error) {
	var identity Identity
	if c.legacyExtender {
		var status struct {
			Result string `json:"result"`
			Object []struct {
				DeviceInfo Identity `json:"DeviceInfo"`
			} `json:"Object"`
		}
		if err := c.getProtectedJSON(ctx, "/cgi-bin/DAL?oid=status", &status); err != nil {
			return Identity{}, err
		}
		if status.Result != "ZCFG_SUCCESS" || len(status.Object) != 1 {
			return Identity{}, fmt.Errorf("%w: extender status did not confirm identity", ErrUnauthenticated)
		}
		identity = status.Object[0].DeviceInfo
		if !isLegacyExtender(identity) {
			return Identity{}, errors.New("extender status identity is incomplete or unsupported")
		}
	} else if err := c.getProtectedJSON(ctx, "/cgi-bin/getBasicInformation", &identity); err != nil {
		return Identity{}, err
	}
	if identity.Model == "" || identity.Firmware == "" {
		return Identity{}, errors.New("router identity response is incomplete")
	}
	return identity, nil
}

func (c *Client) WithAuthentication(ctx context.Context, operation func(*Client) error) error {
	relogged := false
	if _, err := c.ValidateSession(ctx); err != nil {
		if !errors.Is(err, ErrUnauthenticated) {
			return err
		}
		if c.prompt == nil || !c.prompt.Interactive() {
			return c.loginRequired("router session is not authenticated")
		}
		if err := c.Login(ctx, c.config.Username); err != nil {
			return err
		}
		relogged = true
	}
	err := operation(c)
	if !errors.Is(err, ErrUnauthenticated) || relogged {
		return err
	}
	if c.prompt == nil || !c.prompt.Interactive() {
		return c.loginRequired("router session expired")
	}
	if err := c.Login(ctx, c.config.Username); err != nil {
		return err
	}
	return operation(c)
}

func (c *Client) loginRequired(reason string) error {
	command := c.loginCommand
	if command == "" {
		command = "zyxelctl login"
	}
	return fmt.Errorf("%s; run %s in a terminal", reason, command)
}

func (c *Client) getPlainJSON(ctx context.Context, path string, target any) error {
	_, data, err := c.requestWithoutSession(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errors.New("router returned invalid public JSON")
	}
	return nil
}

func (c *Client) requestWithoutSession(ctx context.Context, method, path string, body []byte) (*http.Response, []byte, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path})
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
	response, err := c.http.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("router request failed: %w", err)
	}
	defer response.Body.Close()
	c.updateCookies(response.Cookies())
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return response, nil, errors.New("could not read router response")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response, data, fmt.Errorf("router request returned HTTP %d", response.StatusCode)
	}
	return response, data, nil
}
