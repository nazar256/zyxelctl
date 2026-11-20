package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/session"
	"github.com/nazar256/zyxelctl/internal/wifi"
)

type RouterAPI interface {
	Authenticate(context.Context, func() error) error
	Login(context.Context, string) error
	ReadIdentity(context.Context) (router.Identity, error)
	Get(context.Context, string, any) error
}

type LocalStore interface {
	LoadState() (session.State, error)
	Logout() error
}

type Output struct {
	Interactive bool
	Confirm     func(string) (bool, error)
	Password    func(string) (string, error)
	Text        func(string, string) (string, error)
	Probe       func(context.Context, string) (int, error)
	Now         func() time.Time
	Sleep       func(time.Duration)
}

type App struct {
	router RouterAPI
	store  LocalStore
	output Output
}

func New(routerAPI RouterAPI, store LocalStore, output Output) *App {
	if output.Now == nil {
		output.Now = time.Now
	}
	if output.Sleep == nil {
		output.Sleep = time.Sleep
	}
	if output.Probe == nil {
		output.Probe = probeHTTPHead
	}
	return &App{router: routerAPI, store: store, output: output}
}

type ClientAdapter struct {
	Client *router.Client
}

func (a ClientAdapter) Authenticate(ctx context.Context, operation func() error) error {
	return a.Client.WithAuthentication(ctx, func(*router.Client) error { return operation() })
}
func (a ClientAdapter) Login(ctx context.Context, username string) error {
	return a.Client.Login(ctx, username)
}
func (a ClientAdapter) ReadIdentity(ctx context.Context) (router.Identity, error) {
	return a.Client.ReadIdentity(ctx)
}
func (a ClientAdapter) Get(ctx context.Context, path string, target any) error {
	return a.Client.Get(ctx, path, target)
}
func (a ClientAdapter) Put(ctx context.Context, path string, payload any) error {
	return a.Client.Put(ctx, path, payload)
}
func (a ClientAdapter) Post(ctx context.Context, path string, payload any) error {
	return a.Client.Post(ctx, path, payload)
}
func (a ClientAdapter) Delete(ctx context.Context, path string, payload any) error {
	return a.Client.Delete(ctx, path, payload)
}
func (a ClientAdapter) Download(ctx context.Context, path string) ([]byte, error) {
	return a.Client.Download(ctx, path)
}

type StatusResult struct {
	Identity        router.Identity `json:"identity"`
	DHCPEnabled     bool            `json:"dhcp_enabled"`
	WLANProfiles    int             `json:"wlan_profiles"`
	EnabledProfiles int             `json:"enabled_profiles"`
}

type WiFiSummary struct {
	Index      int    `json:"index"`
	Band       string `json:"band,omitempty"`
	Enabled    bool   `json:"enabled"`
	SSID       string `json:"ssid"`
	Security   string `json:"security"`
	GuestClass string `json:"guest_class"`
}

type IoTResult struct {
	SSID      string        `json:"ssid"`
	HomeGuest bool          `json:"home_guest"`
	Profiles  []WiFiSummary `json:"profiles"`
}

type Client struct {
	IP          string `json:"ip"`
	Name        string `json:"name,omitempty"`
	MAC         string `json:"mac,omitempty"`
	Interface   string `json:"interface"`
	WiFiName    string `json:"wifi_name,omitempty"`
	Band        string `json:"band,omitempty"`
	AccessPoint string `json:"access_point,omitempty"`
}

type WiFiClient struct {
	IP          string `json:"ip,omitempty"`
	Name        string `json:"name,omitempty"`
	MAC         string `json:"mac"`
	SSID        string `json:"ssid,omitempty"`
	Band        string `json:"band,omitempty"`
	BSSID       string `json:"bssid,omitempty"`
	AccessPoint string `json:"access_point,omitempty"`
}

type meshRadio struct {
	Band   string `json:"band"`
	BSSID  string `json:"bssid"`
	SSID   string `json:"ssid"`
	Status string `json:"status"`
}

type meshStation struct {
	MAC   string `json:"station"`
	BSSID string `json:"bssid"`
	SSID  string `json:"ssid"`
	Stale string `json:"stale"`
}

type meshStatus struct {
	ControllerRadios []meshRadio   `json:"result_ctl"`
	ExtenderRadios   []meshRadio   `json:"result_ext"`
	Stations         []meshStation `json:"result_sta"`
}

type lanHostsResponse struct {
	Object []struct {
		Hosts []struct {
			Active      bool   `json:"Active"`
			IP          string `json:"IPAddress"`
			DeviceName  string `json:"DeviceName"`
			HostName    string `json:"HostName"`
			MAC         string `json:"PhysAddress"`
			Interface   string `json:"InterfaceType"`
			WiFiName    string `json:"WiFiname"`
			Band        string `json:"SupportedFrequencyBands"`
			AccessPoint string `json:"X_ZYXEL_ConnectedAP"`
		} `json:"lanhosts"`
	} `json:"Object"`
}

type SessionResult struct {
	Authenticated   bool      `json:"authenticated"`
	Model           string    `json:"model,omitempty"`
	Firmware        string    `json:"firmware,omitempty"`
	LoggedInAt      time.Time `json:"logged_in_at,omitempty"`
	LastValidatedAt time.Time `json:"last_validated_at,omitempty"`
}

type wlanResponse struct {
	Result string         `json:"result"`
	Object []wifi.Profile `json:"Object"`
}

type lanResponse struct {
	Result string `json:"result"`
	Object []struct {
		EnableDHCP bool `json:"EnableDHCP"`
	} `json:"Object"`
}

func (a *App) Login(ctx context.Context, username string) error {
	if a.router == nil {
		return errors.New("router client is unavailable")
	}
	return a.router.Login(ctx, username)
}

func (a *App) Info(ctx context.Context) (router.Identity, error) {
	var identity router.Identity
	err := a.authenticated(ctx, func() error {
		var err error
		identity, err = a.router.ReadIdentity(ctx)
		return err
	})
	return identity, err
}

func (a *App) Status(ctx context.Context) (StatusResult, error) {
	var result StatusResult
	err := a.authenticated(ctx, func() error {
		var err error
		result.Identity, err = a.router.ReadIdentity(ctx)
		if err != nil {
			return err
		}
		var lan lanResponse
		if err := a.router.Get(ctx, "/cgi-bin/DAL?oid=lan", &lan); err != nil {
			return err
		}
		if len(lan.Object) == 0 {
			return errors.New("router returned no LAN configuration")
		}
		result.DHCPEnabled = lan.Object[0].EnableDHCP
		var wlan wlanResponse
		if err := a.router.Get(ctx, "/cgi-bin/DAL?oid=wlan", &wlan); err != nil {
			return err
		}
		result.WLANProfiles = len(wlan.Object)
		for _, profile := range wlan.Object {
			if profile.WLEnable {
				result.EnabledProfiles++
			}
		}
		return nil
	})
	return result, err
}

func (a *App) WiFiList(ctx context.Context) ([]WiFiSummary, error) {
	var response wlanResponse
	err := a.authenticated(ctx, func() error {
		return a.router.Get(ctx, "/cgi-bin/DAL?oid=wlan", &response)
	})
	if err != nil {
		return nil, err
	}
	result := make([]WiFiSummary, 0, len(response.Object))
	for _, profile := range response.Object {
		result = append(result, summarizeProfile(profile))
	}
	return result, nil
}

func (a *App) IoTShow(ctx context.Context) (IoTResult, error) {
	var response wlanResponse
	err := a.authenticated(ctx, func() error {
		return a.router.Get(ctx, "/cgi-bin/DAL?oid=wlan", &response)
	})
	if err != nil {
		return IoTResult{}, err
	}
	profiles := make([]wifi.Profile, 0, 2)
	for _, profile := range response.Object {
		if profile.Index == 3 || profile.Index == 7 {
			profiles = append(profiles, profile)
		}
	}
	inspection := append([]wifi.Profile(nil), profiles...)
	for i := range inspection {
		inspection[i].WLEnable = true
		inspection[i].OneSSIDEnable = true
	}
	if err := wifi.ValidatePair(inspection); err != nil {
		return IoTResult{}, fmt.Errorf("IoT WLAN preflight failed: %w", err)
	}
	return IoTResult{
		SSID:      profiles[0].SSID,
		HomeGuest: wifi.IsHomeGuest(profiles[0]) && wifi.IsHomeGuest(profiles[1]),
		Profiles:  []WiFiSummary{summarizeProfile(profiles[0]), summarizeProfile(profiles[1])},
	}, nil
}

func (a *App) ClientsList(ctx context.Context) ([]Client, error) {
	var response lanHostsResponse
	err := a.authenticated(ctx, func() error {
		return a.router.Get(ctx, "/cgi-bin/DAL?oid=lanhosts", &response)
	})
	if err != nil {
		return nil, err
	}
	if len(response.Object) == 0 {
		return nil, errors.New("router returned no connected-device table")
	}
	result := make([]Client, 0)
	for _, group := range response.Object {
		for _, host := range group.Hosts {
			if !host.Active || host.IP == "" {
				continue
			}
			name := host.DeviceName
			if name == "" {
				name = host.HostName
			}
			result = append(result, Client{IP: host.IP, Name: name, MAC: host.MAC, Interface: host.Interface, WiFiName: host.WiFiName, Band: host.Band, AccessPoint: host.AccessPoint})
		}
	}
	return result, nil
}

func (a *App) WiFiClients(ctx context.Context) ([]WiFiClient, error) {
	var mesh []meshStatus
	var hosts lanHostsResponse
	err := a.authenticated(ctx, func() error {
		if err := a.router.Get(ctx, "/cgi-bin/SteeringStatus_handle", &mesh); err != nil {
			return err
		}
		if len(mesh) == 0 {
			return errors.New("router returned no mesh station table")
		}
		return a.router.Get(ctx, "/cgi-bin/DAL?oid=lanhosts", &hosts)
	})
	if err != nil {
		return nil, err
	}
	if len(hosts.Object) == 0 {
		return nil, errors.New("router returned no connected-device table")
	}

	byMAC := make(map[string]Client)
	for _, group := range hosts.Object {
		for _, host := range group.Hosts {
			if !host.Active || host.IP == "" || host.MAC == "" {
				continue
			}
			name := host.DeviceName
			if name == "" {
				name = host.HostName
			}
			byMAC[strings.ToUpper(host.MAC)] = Client{IP: host.IP, Name: name, AccessPoint: host.AccessPoint}
		}
	}

	radios := make(map[string]meshRadio)
	for _, group := range mesh {
		for _, radio := range append(group.ControllerRadios, group.ExtenderRadios...) {
			if strings.EqualFold(radio.Status, "Up") {
				radios[strings.ToUpper(radio.BSSID)] = radio
			}
		}
	}
	result := make([]WiFiClient, 0)
	for _, group := range mesh {
		for _, station := range group.Stations {
			if !strings.EqualFold(station.Stale, "NO") || station.MAC == "" {
				continue
			}
			client := WiFiClient{MAC: station.MAC, SSID: station.SSID, BSSID: station.BSSID}
			if host, ok := byMAC[strings.ToUpper(station.MAC)]; ok {
				client.IP = host.IP
				client.Name = host.Name
				client.AccessPoint = host.AccessPoint
			}
			if radio, ok := radios[strings.ToUpper(station.BSSID)]; ok {
				switch radio.Band {
				case "2.4G":
					client.Band = "2.4GHz"
				case "5G":
					client.Band = "5GHz"
				}
				if client.SSID == "" {
					client.SSID = radio.SSID
				}
			}
			result = append(result, client)
		}
	}
	return result, nil
}

func (a *App) APIGet(ctx context.Context, path string, showSensitive bool) (any, error) {
	parsed, err := url.Parse(path)
	if err != nil || path == "" || parsed.IsAbs() || parsed.Host != "" || len(path) < 1 || path[0] != '/' || len(path) > 1 && path[1] == '/' {
		return nil, errors.New("API path must be a local absolute path beginning with one slash")
	}
	if showSensitive {
		if !a.output.Interactive || a.output.Confirm == nil {
			return nil, errors.New("showing sensitive router data requires an interactive terminal")
		}
		confirmed, err := a.output.Confirm("Show unredacted sensitive router data?")
		if err != nil {
			return nil, fmt.Errorf("confirm sensitive output: %w", err)
		}
		if !confirmed {
			return nil, errors.New("sensitive output was not confirmed")
		}
	}
	var value any
	err = a.authenticated(ctx, func() error { return a.router.Get(ctx, path, &value) })
	if err != nil {
		return nil, err
	}
	if showSensitive {
		return value, nil
	}
	return router.Redact(value), nil
}

func (a *App) Session() (SessionResult, error) {
	state, err := a.store.LoadState()
	if errors.Is(err, os.ErrNotExist) {
		return SessionResult{}, nil
	}
	if err != nil {
		return SessionResult{}, err
	}
	return SessionResult{
		Authenticated:   state.AESKey != "" && state.CSRFToken != "",
		Model:           state.Model,
		Firmware:        state.Firmware,
		LoggedInAt:      state.LoggedInAt,
		LastValidatedAt: state.LastValidatedAt,
	}, nil
}

func (a *App) Logout() error {
	return a.store.Logout()
}

func (a *App) authenticated(ctx context.Context, operation func() error) error {
	if a.router == nil {
		return errors.New("router client is unavailable")
	}
	return a.router.Authenticate(ctx, operation)
}

func summarizeProfile(profile wifi.Profile) WiFiSummary {
	guestClass := "standard"
	if wifi.IsHomeGuest(profile) {
		guestClass = "home_guest"
	} else if profile.IsolationEnable && profile.BSSIDIsolation {
		guestClass = "external_guest"
	}
	return WiFiSummary{
		Index:      profile.Index,
		Band:       profile.Band,
		Enabled:    profile.WLEnable,
		SSID:       profile.SSID,
		Security:   profile.SecurityMode,
		GuestClass: guestClass,
	}
}
