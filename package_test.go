package zyxelctl_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetupScriptDelegatesInteractivePromptsToCLI(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	record := filepath.Join(tmp, "args")
	fake := filepath.Join(tmp, "zyxelctl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$ZYXELCTL_TEST_RECORD\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "setup-iot-guest.sh")
	command.Env = append(os.Environ(),
		"ZYXELCTL_BIN="+fake,
		"ZYXELCTL_TEST_RECORD="+record,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("setup script failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "iot\nconfigure\n"; got != want {
		t.Fatalf("delegated arguments = %q, want %q", got, want)
	}
}

func TestInstalledSetupScriptFindsSiblingCLI(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	record := filepath.Join(tmp, "args")
	setupData, err := os.ReadFile("setup-iot-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	setup := filepath.Join(tmp, "setup-iot-guest")
	if err := os.WriteFile(setup, setupData, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(tmp, "zyxelctl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$ZYXELCTL_TEST_RECORD\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(setup)
	command.Env = append(os.Environ(),
		"PATH=/usr/bin:/bin",
		"ZYXELCTL_TEST_RECORD="+record,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installed setup script failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "iot\nconfigure\n"; got != want {
		t.Fatalf("delegated arguments = %q, want %q", got, want)
	}
}

func TestMakeInstallProducesRunnableEntryPoints(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the command")
	}
	prefix := t.TempDir()
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.Command("make", "install", "PREFIX="+prefix, "GO="+goBinary)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("make install failed: %v\n%s", err, output)
	}

	for _, name := range []string{"zyxelctl", "setup-iot-guest"} {
		path := filepath.Join(prefix, "bin", name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode = %o, want 755", name, info.Mode().Perm())
		}
		output, err := exec.Command(path, "--help").CombinedOutput()
		if err != nil {
			t.Fatalf("%s --help failed: %v\n%s", name, err, output)
		}
		if !strings.Contains(string(output), "zyxelctl") {
			t.Fatalf("%s --help did not identify zyxelctl: %s", name, output)
		}
	}
}
