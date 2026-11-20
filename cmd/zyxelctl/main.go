package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strings"

	"golang.org/x/term"

	"github.com/nazar256/zyxelctl/internal/app"
	"github.com/nazar256/zyxelctl/internal/router"
	"github.com/nazar256/zyxelctl/internal/session"
)

type commandService interface {
	Login(context.Context, string) error
	Logout() error
	Session() (app.SessionResult, error)
	Info(context.Context) (router.Identity, error)
	Status(context.Context) (app.StatusResult, error)
	WiFiList(context.Context) ([]app.WiFiSummary, error)
	SetBandSync(context.Context, bool, bool) (app.ConfigureResult, error)
	ClientsList(context.Context) ([]app.Client, error)
	WiFiClients(context.Context) ([]app.WiFiClient, error)
	IoTShow(context.Context) (app.IoTResult, error)
	ConfigureIoTSubnet(context.Context, string, string, string, bool, bool) (app.ConfigureResult, error)
	APIGet(context.Context, string, bool) (any, error)
	ConfigBackup(context.Context, string) (app.BackupResult, error)
	WiFiSnapshot(context.Context, string) (app.BackupResult, error)
	WiFiRestore(context.Context, string, bool) (app.ConfigureResult, error)
	ConfigureIoT(context.Context, string, bool) (app.ConfigureResult, error)
	EnableIoTPeerAccess(context.Context, bool) (app.ConfigureResult, error)
	SetExtenderIoTHomeGuest(context.Context, bool) (app.ConfigureResult, error)
	SetIoTBroadcast(context.Context, bool, bool) (app.ConfigureResult, error)
	ReserveIoTIP(context.Context, string, string, bool) (app.ConfigureResult, error)
	RecreateIoTReservation(context.Context, string, string, bool) (app.ConfigureResult, error)
	ClearIoTReservations(context.Context, bool, bool, []string) (app.ClearReservationsResult, error)
	RestartIoTRadio(context.Context, bool) (app.RadioRestartResult, error)
	ProbeIoTIsolation(context.Context, string, bool) (app.IsolationProbeResult, error)
}

type stdioPrompt struct {
	in          *os.File
	out         io.Writer
	interactive bool
	device      string
}

func (p *stdioPrompt) Interactive() bool { return p.interactive }
func (p *stdioPrompt) Confirm(message string) (bool, error) {
	if !p.interactive {
		return false, errors.New("interactive terminal required")
	}
	fmt.Fprintf(p.out, "%s [y/N] ", message)
	line, err := bufio.NewReader(p.in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
func (p *stdioPrompt) Password(message string) (string, error) {
	if !p.interactive {
		return "", errors.New("interactive terminal required")
	}
	if p.device == "extender" && message == "Router password: " {
		message = "Extender password: "
	}
	fmt.Fprint(p.out, message)
	value, err := term.ReadPassword(int(p.in.Fd()))
	fmt.Fprintln(p.out)
	if err != nil {
		return "", err
	}
	return string(value), nil
}
func (p *stdioPrompt) Text(message, fallback string) (string, error) {
	if !p.interactive {
		return fallback, nil
	}
	fmt.Fprint(p.out, message)
	line, err := bufio.NewReader(p.in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return fallback, nil
	}
	return value, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	device, args, err := parseDeviceArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		printUsage(stdout)
		return 0
	}
	if err != nil {
		return usageError(stderr, err.Error())
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "zyxelctl: cannot determine home directory")
		return 1
	}
	basePaths := session.NewPaths(map[string]string{
		"XDG_CONFIG_HOME": os.Getenv("XDG_CONFIG_HOME"),
		"XDG_STATE_HOME":  os.Getenv("XDG_STATE_HOME"),
	}, home)
	paths, err := basePaths.ForDevice(device)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	store := session.NewStore(paths)
	prompt := &stdioPrompt{in: stdin, out: stderr, interactive: term.IsTerminal(int(stdin.Fd())), device: device}

	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printUsage(stdout)
		return 0
	}
	if args[0] == "version" {
		fmt.Fprintf(stdout, "{\n  \"version\": %q\n}\n", buildVersion())
		return 0
	}
	if args[0] == "session" || args[0] == "logout" {
		return execute(context.Background(), args, app.New(nil, store, app.Output{}), stdout, stderr)
	}
	args, err = prepareLoginArgs(args, prompt)
	if err != nil {
		fmt.Fprintf(stderr, "zyxelctl: %v\n", err)
		return 1
	}

	options := router.LoginOptions{DeviceName: device}
	if device == "extender" {
		options.LoginCommand = "zyxelctl extender-login"
	}
	var loginOptions loginFlags
	if args[0] == "login" {
		loginOptions, err = parseLoginFlags(args[1:], device)
		if err != nil {
			return usageError(stderr, err.Error())
		}
		options.ReplaceCertificate = loginOptions.replaceCertificate
		options.RouterURL = loginOptions.url
		options.Username = loginOptions.username
	}
	options.RouterURL, err = deviceURL(store, device, options.RouterURL)
	if err != nil {
		fmt.Fprintln(stderr, "zyxelctl:", err)
		return 1
	}
	client, err := router.Connect(context.Background(), store, prompt, options)
	if err != nil {
		fmt.Fprintf(stderr, "zyxelctl: %v\n", err)
		return 1
	}
	if args[0] == "login" && loginOptions.withExtender {
		return combinedLogin(context.Background(), client, basePaths, prompt, loginOptions, stdout, stderr)
	}
	service := app.New(app.ClientAdapter{Client: client}, store, app.Output{
		Interactive: prompt.Interactive(),
		Confirm:     prompt.Confirm,
		Password:    prompt.Password,
		Text:        prompt.Text,
	})
	return execute(context.Background(), args, service, stdout, stderr)
}

func execute(ctx context.Context, args []string, service commandService, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	var value any
	var err error
	switch args[0] {
	case "login":
		flags := flag.NewFlagSet("login", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		username := flags.String("username", router.DefaultUsername, "router username")
		_ = flags.Bool("replace-certificate", false, "replace pinned certificate")
		_ = flags.String("url", "", "device HTTPS address")
		if parseErr := flags.Parse(args[1:]); parseErr != nil || flags.NArg() != 0 {
			return usageError(stderr, "usage: zyxelctl login [--username USER] [--replace-certificate]")
		}
		err = service.Login(ctx, *username)
		value = map[string]any{"authenticated": err == nil, "username": *username}
	case "logout":
		if len(args) != 1 {
			return usageError(stderr, "usage: zyxelctl logout")
		}
		err = service.Logout()
		value = map[string]any{"authenticated": false}
	case "session":
		if len(args) != 1 {
			return usageError(stderr, "usage: zyxelctl session")
		}
		value, err = service.Session()
	case "info":
		if len(args) != 1 {
			return usageError(stderr, "usage: zyxelctl info")
		}
		value, err = service.Info(ctx)
	case "status":
		if len(args) != 1 {
			return usageError(stderr, "usage: zyxelctl status")
		}
		value, err = service.Status(ctx)
	case "wifi":
		if len(args) < 2 {
			return usageError(stderr, "usage: zyxelctl wifi <list|snapshot|restore|band-sync> ...")
		}
		switch args[1] {
		case "band-sync":
			flags := flag.NewFlagSet("wifi band-sync", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			enabled := flags.Bool("enabled", true, "synchronize Wi-Fi bands")
			yes := flags.Bool("yes", false, "confirm global Wi-Fi change")
			if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 || !flagProvided(args[2:], "--enabled") {
				return usageError(stderr, "usage: zyxelctl wifi band-sync --enabled=true|false [--yes]")
			}
			value, err = service.SetBandSync(ctx, *enabled, *yes)
		case "list":
			if len(args) != 2 {
				return usageError(stderr, "usage: zyxelctl wifi list")
			}
			value, err = service.WiFiList(ctx)
		case "snapshot":
			flags := flag.NewFlagSet("wifi snapshot", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			output := flags.String("output", "", "backup output directory")
			if parseErr := flags.Parse(args[2:]); parseErr != nil || flags.NArg() != 0 {
				return usageError(stderr, "usage: zyxelctl wifi snapshot [--output DIRECTORY]")
			}
			value, err = service.WiFiSnapshot(ctx, *output)
		case "restore":
			if len(args) < 3 {
				return usageError(stderr, "usage: zyxelctl wifi restore FILE [--yes]")
			}
			flags := flag.NewFlagSet("wifi restore", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			yes := flags.Bool("yes", false, "skip confirmation")
			if parseErr := flags.Parse(args[3:]); parseErr != nil || flags.NArg() != 0 {
				return usageError(stderr, "usage: zyxelctl wifi restore FILE [--yes]")
			}
			value, err = service.WiFiRestore(ctx, args[2], *yes)
		default:
			return usageError(stderr, "usage: zyxelctl wifi <list|snapshot|restore|band-sync> ...")
		}
	case "clients":
		if len(args) != 2 {
			return usageError(stderr, "usage: zyxelctl clients <list|wifi>")
		}
		switch args[1] {
		case "list":
			value, err = service.ClientsList(ctx)
		case "wifi":
			value, err = service.WiFiClients(ctx)
		default:
			return usageError(stderr, "usage: zyxelctl clients <list|wifi>")
		}
	case "iot":
		if len(args) < 2 {
			return usageError(stderr, "usage: zyxelctl iot <show|configure|subnet|broadcast|radio-restart|reserve-ip|clear-reservations|allow-peers|probe-isolation|home-guest> ...")
		}
		switch args[1] {
		case "subnet":
			flags := flag.NewFlagSet("iot subnet", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			gateway := flags.String("gateway", "", "IoT gateway/prefix")
			start := flags.String("dhcp-start", "", "first DHCP address")
			end := flags.String("dhcp-end", "", "last DHCP address")
			disable := flags.Bool("disable", false, "remove IoT subnet")
			yes := flags.Bool("yes", false, "confirm IoT address changes")
			if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 || (*disable && (*gateway != "" || *start != "" || *end != "")) || (!*disable && (*gateway == "" || *start == "" || *end == "")) {
				return usageError(stderr, "usage: zyxelctl iot subnet --gateway IPv4/PREFIX --dhcp-start IPv4 --dhcp-end IPv4 [--yes], or iot subnet --disable [--yes]")
			}
			value, err = service.ConfigureIoTSubnet(ctx, *gateway, *start, *end, *disable, *yes)
		case "clear-reservations":
			flags := flag.NewFlagSet("iot clear-reservations", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			dryRun := flags.Bool("dry-run", false, "show current IoT bindings without deleting")
			yes := flags.Bool("yes", false, "confirm deleting current IoT bindings")
			macs := []string{}
			flags.Func("mac", "also clear the reservation of an offline device MAC (repeatable)", func(value string) error {
				hardware, err := net.ParseMAC(value)
				if err != nil || len(hardware) != 6 {
					return errors.New("invalid MAC address")
				}
				macs = append(macs, hardware.String())
				return nil
			})
			if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
				return usageError(stderr, "usage: zyxelctl iot clear-reservations [--dry-run] [--yes] [--mac MAC]...")
			}
			value, err = service.ClearIoTReservations(ctx, *dryRun, *yes, macs)
		case "radio-restart":
			flags := flag.NewFlagSet("iot radio-restart", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			yes := flags.Bool("yes", false, "confirm restarting the IoT guest Wi-Fi on the gateway")
			if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
				return usageError(stderr, "usage: zyxelctl iot radio-restart [--yes]")
			}
			value, err = service.RestartIoTRadio(ctx, *yes)
		case "reserve-ip":
			flags := flag.NewFlagSet("iot reserve-ip", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			mac := flags.String("mac", "", "IoT client MAC address")
			ip := flags.String("ip", "", "reserved IPv4 address")
			yes := flags.Bool("yes", false, "skip confirmation")
			recreate := flags.Bool("recreate", false, "replace the existing binding using the router delete/add flow")
			if parseErr := flags.Parse(args[2:]); parseErr != nil || flags.NArg() != 0 || *mac == "" || *ip == "" {
				return usageError(stderr, "usage: zyxelctl iot reserve-ip --mac MAC --ip IPv4 [--yes]")
			}
			if *recreate {
				value, err = service.RecreateIoTReservation(ctx, *mac, *ip, *yes)
			} else {
				value, err = service.ReserveIoTIP(ctx, *mac, *ip, *yes)
			}
		case "broadcast":
			flags := flag.NewFlagSet("iot broadcast", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			enabled := flags.Bool("enabled", true, "broadcast the IoT WLAN")
			yes := flags.Bool("yes", false, "confirm broadcast change")
			if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 || !flagProvided(args[2:], "--enabled") {
				return usageError(stderr, "usage: zyxelctl [--device router|extender] iot broadcast --enabled=true|false [--yes]")
			}
			value, err = service.SetIoTBroadcast(ctx, *enabled, *yes)
		case "home-guest":
			flags := flag.NewFlagSet("iot home-guest", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			yes := flags.Bool("yes", false, "skip confirmation")
			if parseErr := flags.Parse(args[2:]); parseErr != nil || flags.NArg() != 0 {
				return usageError(stderr, "usage: zyxelctl --device extender iot home-guest [--yes]")
			}
			value, err = service.SetExtenderIoTHomeGuest(ctx, *yes)
		case "show":
			if len(args) != 2 {
				return usageError(stderr, "usage: zyxelctl iot show")
			}
			value, err = service.IoTShow(ctx)
		case "configure":
			flags := flag.NewFlagSet("iot configure", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			ssid := flags.String("ssid", "", "network name")
			yes := flags.Bool("yes", false, "skip confirmation")
			if parseErr := flags.Parse(args[2:]); parseErr != nil || flags.NArg() != 0 {
				return usageError(stderr, "usage: zyxelctl iot configure [--ssid NAME] [--yes]")
			}
			value, err = service.ConfigureIoT(ctx, *ssid, *yes)
		case "allow-peers":
			flags := flag.NewFlagSet("iot allow-peers", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			yes := flags.Bool("yes", false, "skip confirmation")
			if parseErr := flags.Parse(args[2:]); parseErr != nil || flags.NArg() != 0 {
				return usageError(stderr, "usage: zyxelctl iot allow-peers [--yes]")
			}
			value, err = service.EnableIoTPeerAccess(ctx, *yes)
		case "probe-isolation":
			flags := flag.NewFlagSet("iot probe-isolation", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			target := flags.String("target", "", "private HTTP URL to probe")
			yes := flags.Bool("yes", false, "skip confirmation")
			if parseErr := flags.Parse(args[2:]); parseErr != nil || flags.NArg() != 0 || *target == "" {
				return usageError(stderr, "usage: zyxelctl iot probe-isolation --target http://PRIVATE_IP:PORT/ [--yes]")
			}
			value, err = service.ProbeIoTIsolation(ctx, *target, *yes)
		default:
			return usageError(stderr, "usage: zyxelctl iot <show|configure|subnet|broadcast|radio-restart|reserve-ip|clear-reservations|allow-peers|probe-isolation|home-guest> ...")
		}
	case "config":
		if len(args) < 2 || args[1] != "backup" {
			return usageError(stderr, "usage: zyxelctl config backup [--output DIRECTORY]")
		}
		flags := flag.NewFlagSet("config backup", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		output := flags.String("output", "", "backup output directory")
		if parseErr := flags.Parse(args[2:]); parseErr != nil || flags.NArg() != 0 {
			return usageError(stderr, "usage: zyxelctl config backup [--output DIRECTORY]")
		}
		value, err = service.ConfigBackup(ctx, *output)
	case "api":
		if len(args) < 3 || args[1] != "get" {
			return usageError(stderr, "usage: zyxelctl api get PATH [--show-sensitive]")
		}
		flags := flag.NewFlagSet("api get", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		showSensitive := flags.Bool("show-sensitive", false, "show unredacted data")
		if parseErr := flags.Parse(args[3:]); parseErr != nil || flags.NArg() != 0 {
			return usageError(stderr, "usage: zyxelctl api get PATH [--show-sensitive]")
		}
		value, err = service.APIGet(ctx, args[2], *showSensitive)
	default:
		return usageError(stderr, "unknown command")
	}
	if err != nil {
		fmt.Fprintf(stderr, "zyxelctl: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(stderr, "zyxelctl: could not encode output")
		return 1
	}
	return 0
}

func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "zyxelctl: %s\n", message)
	return 2
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: zyxelctl [--device router|extender] <login|logout|session|info|status|wifi|clients|iot|config|api|version> ...")
	fmt.Fprintln(output, "       zyxelctl extender-login [--url HTTPS_URL] [--username USER] [--replace-certificate]")
	fmt.Fprintln(output, "       zyxelctl login --with-extender [--extender-url HTTPS_URL] [--username USER]")
}

type textPrompter interface {
	Text(message, fallback string) (string, error)
}

func prepareLoginArgs(args []string, prompt textPrompter) ([]string, error) {
	if len(args) == 0 || args[0] != "login" || flagProvided(args[1:], "--username") {
		return args, nil
	}
	username, err := prompt.Text("Username [admin]: ", router.DefaultUsername)
	if err != nil {
		return nil, fmt.Errorf("read router username: %w", err)
	}
	result := append([]string(nil), args...)
	return append(result, "--username", username), nil
}

func flagProvided(args []string, name string) bool {
	for _, argument := range args {
		if argument == name || strings.HasPrefix(argument, name+"=") {
			return true
		}
	}
	return false
}
