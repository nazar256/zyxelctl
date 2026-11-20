package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/session"
)

func parseDeviceArgs(args []string) (string, []string, error) {
	flags := flag.NewFlagSet("zyxelctl", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	device := flags.String("device", "router", "router or extender")
	if err := flags.Parse(args); err != nil {
		return "", nil, err
	}
	if *device != "router" && *device != "extender" {
		return "", nil, errors.New("device must be router or extender")
	}
	command := flags.Args()
	if len(command) > 1 && command[0] == "iot" && command[1] == "home-guest" && *device != "extender" {
		return "", nil, fmt.Errorf("iot %s requires --device extender", command[1])
	}
	if len(command) > 0 && command[0] == "extender-login" {
		deviceSpecified := false
		flags.Visit(func(f *flag.Flag) { deviceSpecified = deviceSpecified || f.Name == "device" })
		if deviceSpecified && *device != "extender" {
			return "", nil, errors.New("extender-login requires the extender device")
		}
		*device = "extender"
		command = append([]string{"login"}, command[1:]...)
	}
	if *device == "extender" && !extenderCommandAllowed(command) {
		return "", nil, errors.New("extender supports read-only commands, iot home-guest, iot broadcast and iot radio-restart; other router mutations are not available for this device")
	}
	return *device, command, nil
}

func extenderCommandAllowed(args []string) bool {
	if len(args) == 0 {
		return true
	}
	switch args[0] {
	case "login", "logout", "session", "info", "status", "help", "--help", "-h":
		return true
	case "wifi":
		return len(args) > 1 && (args[1] == "list" || args[1] == "snapshot")
	case "clients":
		return len(args) > 1 && (args[1] == "list" || args[1] == "wifi")
	case "iot":
		return len(args) > 1 && (args[1] == "show" || args[1] == "home-guest" || args[1] == "broadcast" || args[1] == "radio-restart")
	case "config":
		return len(args) > 1 && args[1] == "backup"
	case "api":
		return len(args) > 1 && args[1] == "get"
	}
	return false
}

type loginFlags struct {
	username, url, extenderURL string
	replaceCertificate         bool
	withExtender               bool
}

func parseLoginFlags(args []string, device string) (loginFlags, error) {
	var options loginFlags
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.username, "username", router.DefaultUsername, "administrator username")
	flags.StringVar(&options.url, "url", "", "device HTTPS address")
	flags.BoolVar(&options.replaceCertificate, "replace-certificate", false, "review a changed device certificate")
	flags.BoolVar(&options.withExtender, "with-extender", false, "use one password for the router and configured extender")
	flags.StringVar(&options.extenderURL, "extender-url", "", "extender HTTPS address for combined login")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, errors.New("usage: zyxelctl login [--username USER] [--url HTTPS_URL] [--replace-certificate] [--with-extender [--extender-url HTTPS_URL]]")
	}
	if device == "extender" && (options.withExtender || options.extenderURL != "") {
		return options, errors.New("combined login must start with the router device")
	}
	if options.extenderURL != "" && !options.withExtender {
		return options, errors.New("--extender-url requires --with-extender")
	}
	return options, nil
}

func deviceURL(store *session.Store, device, explicitURL string) (string, error) {
	if explicitURL != "" || device == "router" {
		return explicitURL, nil
	}
	config, err := store.LoadConfig()
	if errors.Is(err, os.ErrNotExist) || (err == nil && config.RouterURL == "") {
		return "", errors.New("extender address is not configured; run zyxelctl extender-login --url HTTPS_URL")
	}
	if err != nil {
		return "", fmt.Errorf("load extender configuration: %w", err)
	}
	return config.RouterURL, nil
}

type deviceLoginResult struct {
	Authenticated bool   `json:"authenticated"`
	Error         string `json:"error,omitempty"`
	Skipped       bool   `json:"skipped,omitempty"`
}

func combinedLogin(ctx context.Context, gateway *router.Client, basePaths session.Paths, prompt *stdioPrompt, options loginFlags, stdout, stderr io.Writer) int {
	paths, err := basePaths.ForDevice("extender")
	if err != nil {
		fmt.Fprintln(stderr, "zyxelctl:", err)
		return 1
	}
	store := session.NewStore(paths)
	address, err := deviceURL(store, "extender", options.extenderURL)
	if err != nil {
		fmt.Fprintln(stderr, "zyxelctl:", err)
		return 1
	}
	// Both device certificates must be trusted before a shared password is read.
	extender, err := router.Connect(ctx, store, prompt, router.LoginOptions{RouterURL: address, ReplaceCertificate: options.replaceCertificate, LoginCommand: "zyxelctl extender-login", DeviceName: "extender"})
	if err != nil {
		fmt.Fprintln(stderr, "zyxelctl: connect extender:", err)
		return 1
	}
	config, err := store.LoadConfig()
	if err != nil {
		fmt.Fprintln(stderr, "zyxelctl: load extender username:", err)
		return 1
	}
	password, err := prompt.Password("Router and extender password: ")
	if err != nil {
		fmt.Fprintln(stderr, "zyxelctl: read administrator password:", err)
		return 1
	}
	result := struct {
		Router   deviceLoginResult `json:"router"`
		Extender deviceLoginResult `json:"extender"`
	}{Extender: deviceLoginResult{Skipped: true}}
	if err := gateway.LoginWithPassword(ctx, options.username, password); err != nil {
		result.Router.Error = err.Error()
	} else {
		result.Router.Authenticated = true
		result.Extender.Skipped = false
		if err := extender.LoginWithPassword(ctx, config.Username, password); err != nil {
			result.Extender.Error = err.Error()
		} else {
			result.Extender.Authenticated = true
		}
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, "zyxelctl: encode login result:", err)
		return 1
	}
	if !result.Router.Authenticated || !result.Extender.Authenticated {
		return 1
	}
	return 0
}
