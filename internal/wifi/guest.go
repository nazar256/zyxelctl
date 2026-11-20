package wifi

import (
	"errors"
	"net"
	"net/netip"
)

// GuestPairSSID identifies the managed guest network structurally: the
// non-main profiles at indexes 3 and 7 sharing one non-empty SSID that
// differs from the main pair's names. The configured name is read from the
// device at runtime; no site-specific name is ever hardcoded.
func GuestPairSSID(profiles []Profile) (string, error) {
	byIndex := make(map[int]Profile, len(profiles))
	for _, p := range profiles {
		byIndex[p.Index] = p
	}
	p3, ok3 := byIndex[3]
	p7, ok7 := byIndex[7]
	if !ok3 || !ok7 || p3.Extra["MainSSID"] != false || p7.Extra["MainSSID"] != false || p3.Band != "2.4GHz" || p7.Band != "5GHz" {
		return "", errors.New("expected the non-main guest profile pair on indexes 3 and 7")
	}
	if p3.SSID == "" || p3.SSID != p7.SSID {
		return "", errors.New("expected matching guest network names on profiles 3 and 7")
	}
	if byIndex[1].SSID == p3.SSID || byIndex[5].SSID == p3.SSID {
		return "", errors.New("guest network name matches a main network")
	}
	return p3.SSID, nil
}

// GuestSubnet returns the dedicated subnet configured on the managed guest
// pair's 2.4GHz profile, or an invalid Prefix when the subnet feature is off.
func GuestSubnet(profiles []Profile) (netip.Prefix, error) {
	for _, p := range profiles {
		if p.Index != profile24GHz || p.Extra["MainSSID"] != false {
			continue
		}
		if p.Extra["wlSubnetState"] != true {
			return netip.Prefix{}, nil
		}
		address, _ := p.Extra["LANIP"].(string)
		maskText, _ := p.Extra["SubnetMask"].(string)
		gateway, err := netip.ParseAddr(address)
		maskIP := net.ParseIP(maskText).To4()
		if err != nil || !gateway.Is4() || maskIP == nil {
			return netip.Prefix{}, errors.New("enabled guest subnet is missing a valid gateway or mask")
		}
		ones, bits := net.IPMask(maskIP).Size()
		if ones < 1 || bits != 32 || ones > 30 {
			return netip.Prefix{}, errors.New("unsupported guest subnet mask")
		}
		return netip.PrefixFrom(gateway, ones), nil
	}
	return netip.Prefix{}, nil
}
