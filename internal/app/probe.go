package app

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"
)

func validateProbeTarget(target string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("probe target must be an HTTP URL without credentials or a fragment")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.Is4() || !(address.IsPrivate() || address.IsLoopback()) {
		return errors.New("probe target must use a literal private IPv4 address")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("probe target must include a valid TCP port")
	}
	return nil
}

func probeHTTPHead(ctx context.Context, target string) (int, error) {
	if err := validateProbeTarget(target); err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}
