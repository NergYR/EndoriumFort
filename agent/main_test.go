package main

import (
	"strings"
	"testing"
)

func TestParseDeepLinkValid(t *testing.T) {
	raw := "endoriumfort://connect?server=https%3A%2F%2Fendorium.space&token=eft_demo&resource=2&local-port=35739&redirect-url=https%3A%2F%2F127.0.0.1%3A%7B%7BLOCAL_PORT%7D%7D%2F"
	cfg, err := parseDeepLink(raw)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.ServerURL != "https://endorium.space" {
		t.Fatalf("unexpected server: %s", cfg.ServerURL)
	}
	if cfg.Token != "eft_demo" {
		t.Fatalf("unexpected token: %s", cfg.Token)
	}
	if cfg.ResourceID != 2 {
		t.Fatalf("unexpected resource id: %d", cfg.ResourceID)
	}
	if cfg.LocalPort != 35739 {
		t.Fatalf("unexpected local port: %d", cfg.LocalPort)
	}
}

func TestParseDeepLinkRejectsInvalidScheme(t *testing.T) {
	_, err := parseDeepLink("https://endorium.space")
	if err == nil {
		t.Fatal("expected error for invalid scheme")
	}
}

func TestBuildRedirectURLTemplate(t *testing.T) {
	cfg := DeepLinkConfig{
		ServerURL:   "https://endorium.space",
		ResourceID:  12,
		LocalPort:   41000,
		RedirectURL: "https://example.local/open?rid={{RESOURCE_ID}}&port={{LOCAL_PORT}}&srv={{SERVER_URL}}",
	}
	out := buildRedirectURL(cfg)
	if !strings.Contains(out, "rid=12") {
		t.Fatalf("resource replacement missing: %s", out)
	}
	if !strings.Contains(out, "port=41000") {
		t.Fatalf("port replacement missing: %s", out)
	}
	if !strings.Contains(out, "srv=https://endorium.space") {
		t.Fatalf("server replacement missing: %s", out)
	}
}

func TestParseTunnelSpecsValid(t *testing.T) {
	specs, err := parseTunnelSpecs([]string{"3:8888", "7:8890"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0].ResourceID != 3 || specs[0].LocalPort != 8888 {
		t.Fatalf("unexpected first spec: %+v", specs[0])
	}
	if specs[1].ResourceID != 7 || specs[1].LocalPort != 8890 {
		t.Fatalf("unexpected second spec: %+v", specs[1])
	}
}

func TestParseTunnelSpecsRejectsDuplicatePort(t *testing.T) {
	_, err := parseTunnelSpecs([]string{"3:8888", "7:8888"})
	if err == nil {
		t.Fatal("expected duplicate port error")
	}
	if !strings.Contains(err.Error(), "dupli") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseTunnelSpecsRejectsInvalidFormat(t *testing.T) {
	_, err := parseTunnelSpecs([]string{"3-8888"})
	if err == nil {
		t.Fatal("expected invalid format error")
	}
}

func TestTunnelFlagSetRejectsEmpty(t *testing.T) {
	var tf tunnelFlag
	if err := tf.Set("   "); err == nil {
		t.Fatal("expected error for empty spec")
	}
}

func TestZeroBytes(t *testing.T) {
	buf := []byte("supersecret")
	zeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("expected zero at index %d", i)
		}
	}
}

func TestTokenFileRoundtripWithStrictPermissions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const token = "eft_test_token"
	if err := saveTokenSecure(token); err != nil {
		t.Fatalf("saveTokenSecure failed: %v", err)
	}
	loaded, err := loadTokenFromFile()
	if err != nil {
		t.Fatalf("loadTokenFromFile failed: %v", err)
	}
	if loaded != token {
		t.Fatalf("expected %q, got %q", token, loaded)
	}
}
