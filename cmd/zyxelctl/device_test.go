package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nazar256/zyxelctl/internal/session"
)

func TestDeviceSelectionIsExplicitAndExtenderMutationsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		device  string
		command []string
	}{
		{[]string{"info"}, "router", []string{"info"}},
		{[]string{"--device", "extender", "wifi", "list"}, "extender", []string{"wifi", "list"}},
		{[]string{"--device=extender", "session"}, "extender", []string{"session"}},
		{[]string{"--device", "extender", "iot", "home-guest", "--yes"}, "extender", []string{"iot", "home-guest", "--yes"}},
		{[]string{"--device", "extender", "iot", "radio-restart", "--yes"}, "extender", []string{"iot", "radio-restart", "--yes"}},
		{[]string{"extender-login", "--url", "https://192.168.1.219"}, "extender", []string{"login", "--url", "https://192.168.1.219"}},
	} {
		device, command, err := parseDeviceArgs(tc.args)
		if err != nil || device != tc.device || !reflect.DeepEqual(command, tc.command) {
			t.Fatalf("%v => device=%s, command=%v, err=%v", tc.args, device, command, err)
		}
	}
	for _, args := range [][]string{
		{"--device", "../router", "info"},
		{"--device", "router", "extender-login"},
		{"-device", "router", "extender-login"},
		{"--device", "extender", "wifi", "restore", "snapshot.json"},
		{"--device", "extender", "iot", "configure", "--yes"},
		{"--device", "extender", "iot", "probe-isolation", "--yes"},
		{"iot", "home-guest", "--yes"},
	} {
		if _, _, err := parseDeviceArgs(args); err == nil {
			t.Fatalf("invalid target or mutation was accepted: %v", args)
		}
	}
}

func TestCombinedLoginFlagsRequireExplicitRouterScope(t *testing.T) {
	options, err := parseLoginFlags([]string{"--with-extender", "--extender-url", "https://192.168.1.219", "--username", "operator"}, "router")
	if err != nil || !options.withExtender || options.extenderURL != "https://192.168.1.219" || options.username != "operator" {
		t.Fatalf("combined login options = %#v, %v", options, err)
	}
	for _, tc := range []struct {
		device string
		args   []string
	}{
		{"extender", []string{"--with-extender"}},
		{"router", []string{"--extender-url", "https://192.168.1.219"}},
		{"router", []string{"unexpected"}},
	} {
		if _, err := parseLoginFlags(tc.args, tc.device); err == nil {
			t.Fatalf("invalid login options accepted: %v", tc.args)
		}
	}
}

func TestUnconfiguredExtenderCannotFallBackToRouterAddress(t *testing.T) {
	root := t.TempDir()
	store := session.NewStore(session.Paths{ConfigFile: filepath.Join(root, "extender", "config.json")})
	if _, err := deviceURL(store, "extender", ""); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing extender address error = %v", err)
	}
	if _, err := os.Stat(store.Paths.ConfigFile); !os.IsNotExist(err) {
		t.Fatalf("address lookup unexpectedly created a config: %v", err)
	}
}
