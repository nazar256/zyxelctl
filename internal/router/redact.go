package router

import (
	"reflect"
	"regexp"
)

var sensitiveKey = regexp.MustCompile(
	`(?i)(password|passwd|passphrase|psk|secret|privatekey|publickey|sessionkey|csrf|ssid|bssid|macaddress|physaddress|serialnumber|imei|imsi|username|useraccount|sipaccount|externalip|wanip|publicip|hostname)|` +
		`^(ipaddress|ipaddr|macaddr|devicename|wifiname|station|x_zyxel_connectedap|minaddress|maxaddress|subnetmask|radiusserveripaddr)$`,
)

// Redact returns a deep redacted copy of JSON-like router data.
func Redact(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if sensitiveKey.MatchString(key) && !isBoolean(item) {
				result[key] = "[redacted]"
				continue
			}
			result[key] = Redact(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for i, item := range typed {
			result[i] = Redact(item)
		}
		return result
	default:
		return value
	}
}

func isBoolean(value any) bool {
	return value != nil && reflect.TypeOf(value).Kind() == reflect.Bool
}
