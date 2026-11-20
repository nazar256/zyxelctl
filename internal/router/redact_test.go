package router

import (
	"reflect"
	"testing"
)

func TestRedactRecursivelyProtectsSensitiveValues(t *testing.T) {
	input := map[string]any{
		"ModelName": "EX5601-T1",
		"SSID":      "IoT-LAB",
		"enabled":   true,
		"nested": []any{
			map[string]any{"PskDisplay": "wifi-secret", "IsolationEnable": true},
			map[string]any{"MACAddress": "aa:bb:cc:dd:ee:ff", "count": float64(2)},
		},
		"CSRFToken": "token-secret",
	}
	want := map[string]any{
		"ModelName": "EX5601-T1",
		"SSID":      "[redacted]",
		"enabled":   true,
		"nested": []any{
			map[string]any{"PskDisplay": "[redacted]", "IsolationEnable": true},
			map[string]any{"MACAddress": "[redacted]", "count": float64(2)},
		},
		"CSRFToken": "[redacted]",
	}
	if got := Redact(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Redact() = %#v, want %#v", got, want)
	}
	if input["SSID"] != "IoT-LAB" {
		t.Fatal("Redact mutated its input")
	}
}

func TestRedactProtectsRouterNetworkIdentityFields(t *testing.T) {
	input := map[string]any{
		"Object": []any{map[string]any{
			"IPAddress":           "192.0.2.10",
			"IPAddr":              "192.0.2.11",
			"MACAddr":             "02:00:5e:00:00:01",
			"DeviceName":          "Lab Sensor",
			"WiFiname":            "IoT-Lab",
			"STATION":             "02:00:5e:00:00:02",
			"X_ZYXEL_ConnectedAP": "Lab AP",
			"MinAddress":          "192.0.2.10",
			"MaxAddress":          "192.0.2.99",
			"SubnetMask":          "255.255.255.0",
			"RadiusServerIPAddr":  "192.0.2.100",
			"stationCount":        float64(2),
			"ConnectionStatus":    "up",
		}},
	}
	want := map[string]any{
		"Object": []any{map[string]any{
			"IPAddress":           "[redacted]",
			"IPAddr":              "[redacted]",
			"MACAddr":             "[redacted]",
			"DeviceName":          "[redacted]",
			"WiFiname":            "[redacted]",
			"STATION":             "[redacted]",
			"X_ZYXEL_ConnectedAP": "[redacted]",
			"MinAddress":          "[redacted]",
			"MaxAddress":          "[redacted]",
			"SubnetMask":          "[redacted]",
			"RadiusServerIPAddr":  "[redacted]",
			"stationCount":        float64(2),
			"ConnectionStatus":    "up",
		}},
	}
	if got := Redact(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Redact() = %#v, want %#v", got, want)
	}
}

func TestRedactSensitiveBooleanRemainsBoolean(t *testing.T) {
	input := map[string]any{"PasswordEnabled": false}
	want := map[string]any{"PasswordEnabled": false}
	if got := Redact(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Redact() = %#v, want %#v", got, want)
	}
}
