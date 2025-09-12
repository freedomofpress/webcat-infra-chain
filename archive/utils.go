package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

func normalizeHostname(host string) (string, error) {
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return idna.Lookup.ToASCII(trimmed)
}

func fetchPolicyHash(host string) (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Head("https://" + host)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	hash := resp.Header.Get("X-Webcat-Policy-Hash")
	if hash == "" {
		return "", fmt.Errorf("missing X-Webcat-Policy-Hash")
	}
	return hash, nil
}
