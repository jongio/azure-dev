// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azdext

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

// SSRFGuard validates URLs against Server-Side Request Forgery (SSRF) attack
// patterns. It provides standalone SSRF protection for extension authors who
// need URL validation outside of MCP contexts.
//
// SSRFGuard uses a fluent builder pattern for configuration:
//
//	guard := azdext.NewSSRFGuard().
//	    BlockMetadataEndpoints().
//	    BlockPrivateNetworks().
//	    RequireHTTPS()
//
//	if err := guard.Check("http://169.254.169.254/metadata"); err != nil {
//	    // blocked: cloud metadata endpoint
//	}
//
// Use [DefaultSSRFGuard] for a preset configuration that blocks metadata
// endpoints, private networks, and requires HTTPS.
//
// SSRFGuard is safe for concurrent use from multiple goroutines.
type SSRFGuard struct {
	mu            sync.RWMutex
	blockMetadata bool
	blockPrivate  bool
	requireHTTPS  bool
	blockedCIDRs  []*net.IPNet
	blockedHosts  map[string]bool
	allowedHosts  map[string]bool
	// lookupHost is used for DNS resolution; override in tests.
	lookupHost func(string) ([]string, error)
}

// SSRFError describes why a URL was rejected by the [SSRFGuard].
type SSRFError struct {
	// URL is the rejected URL (or a sanitized representation).
	URL string

	// Reason is a machine-readable tag for the violation type.
	// Values: "blocked_host", "blocked_ip", "private_network",
	// "metadata_endpoint", "dns_failure", "https_required",
	// "invalid_url", "scheme_blocked".
	Reason string

	// Detail is a human-readable explanation.
	Detail string
}

func (e *SSRFError) Error() string {
	return fmt.Sprintf("azdext.SSRFGuard: %s: %s (url=%s)", e.Reason, e.Detail, e.URL)
}

// NewSSRFGuard creates an empty SSRF guard with no active protections.
// Use the builder methods to configure protections, or use [DefaultSSRFGuard]
// for a preset secure configuration.
func NewSSRFGuard() *SSRFGuard {
	return &SSRFGuard{
		blockedHosts: make(map[string]bool),
		allowedHosts: make(map[string]bool),
		lookupHost:   net.LookupHost,
	}
}

// DefaultSSRFGuard returns a guard preconfigured with:
//   - Cloud metadata endpoint blocking (AWS, Azure, GCP, Alibaba)
//   - Private network blocking (RFC 1918, loopback, link-local, CGNAT, IPv6 ULA,
//     6to4, Teredo, NAT64)
//   - HTTPS enforcement (except localhost)
//
// This is the recommended starting point for extension authors.
func DefaultSSRFGuard() *SSRFGuard {
	return NewSSRFGuard().
		BlockMetadataEndpoints().
		BlockPrivateNetworks().
		RequireHTTPS()
}

// BlockMetadataEndpoints blocks well-known cloud metadata service endpoints:
//   - 169.254.169.254 (AWS, Azure, most cloud providers)
//   - fd00:ec2::254 (AWS EC2 IPv6 metadata)
//   - metadata.google.internal (GCP)
//   - 100.100.100.200 (Alibaba Cloud)
func (g *SSRFGuard) BlockMetadataEndpoints() *SSRFGuard {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockMetadata = true
	for _, host := range ssrfMetadataHosts {
		g.blockedHosts[strings.ToLower(host)] = true
	}
	return g
}

// BlockPrivateNetworks blocks RFC 1918 private networks, loopback, link-local,
// CGNAT (RFC 6598), and IPv6 transition mechanisms that can embed private IPv4
// addresses (6to4, Teredo, NAT64, IPv4-compatible, IPv4-translated).
func (g *SSRFGuard) BlockPrivateNetworks() *SSRFGuard {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockPrivate = true
	for _, cidr := range ssrfBlockedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			g.blockedCIDRs = append(g.blockedCIDRs, ipNet)
		}
	}
	return g
}

// RequireHTTPS requires HTTPS for all URLs except localhost and loopback
// addresses. HTTP to localhost/127.0.0.1/[::1] is always permitted for
// local development.
func (g *SSRFGuard) RequireHTTPS() *SSRFGuard {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requireHTTPS = true
	return g
}

// AllowHost adds hosts to an explicit allowlist. Allowed hosts bypass all
// IP-based and metadata checks. Host names are compared case-insensitively.
//
// Use this sparingly — over-broad allowlists weaken SSRF protection. Prefer
// allowing specific, known-good endpoints rather than wildcards.
func (g *SSRFGuard) AllowHost(hosts ...string) *SSRFGuard {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, h := range hosts {
		g.allowedHosts[strings.ToLower(h)] = true
	}
	return g
}

// Check validates a URL against the guard's SSRF policy.
//
// Validation order:
//  1. Parse the URL and reject non-HTTP(S) schemes.
//  2. If HTTPS is required, reject plain HTTP to non-localhost hosts.
//  3. Skip further checks if the host is explicitly allowed via [AllowHost].
//  4. Skip further checks for localhost/loopback hosts (local development).
//  5. Reject hosts matching the metadata endpoint blocklist.
//  6. For IP-literal hosts, check directly against blocked CIDRs.
//  7. For hostname hosts, resolve DNS (fail-closed on lookup failure) and
//     check all resolved IPs against blocked CIDRs.
//
// For IPv6 addresses, embedded IPv4 (IPv4-compatible, IPv4-mapped,
// IPv4-translated per RFC 2765) is extracted and re-checked against blocked CIDRs.
//
// Returns nil if the URL is allowed, or a [*SSRFError] describing the violation.
func (g *SSRFGuard) Check(rawURL string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	u, err := url.Parse(rawURL)
	if err != nil {
		return &SSRFError{
			URL:    truncateValue(rawURL, 200),
			Reason: "invalid_url",
			Detail: "URL parsing failed: " + err.Error(),
		}
	}

	host := u.Hostname()

	// Step 1: Scheme validation — only http and https permitted.
	switch u.Scheme {
	case "https":
		// Always allowed.
	case "http":
		if g.requireHTTPS && !isLocalhostHost(host) {
			return &SSRFError{
				URL:    truncateValue(rawURL, 200),
				Reason: "https_required",
				Detail: "HTTPS is required for non-localhost URLs",
			}
		}
	default:
		return &SSRFError{
			URL:    truncateValue(rawURL, 200),
			Reason: "scheme_blocked",
			Detail: fmt.Sprintf("scheme %q is not allowed (only http and https are permitted)", u.Scheme),
		}
	}

	lowerHost := strings.ToLower(host)

	// Step 2: Explicit allowlist bypass.
	if g.allowedHosts[lowerHost] {
		return nil
	}

	// Step 3: Localhost/loopback bypass — localhost is the developer's own
	// machine and is exempt from IP-level SSRF blocking to allow local
	// development workflows (e.g. local API servers, proxies, dev tools).
	if isLocalhostHost(host) {
		return nil
	}

	// Step 5: Metadata endpoint check.
	if g.blockedHosts[lowerHost] {
		return &SSRFError{
			URL:    truncateValue(rawURL, 200),
			Reason: "blocked_host",
			Detail: fmt.Sprintf("host %s is blocked", host),
		}
	}

	// Step 6: IP-based checks.
	if ip := net.ParseIP(host); ip != nil {
		// Direct IP literal — check against blocked ranges.
		return g.checkIPForSSRF(ip, host, rawURL)
	}

	// Step 7: DNS resolution for hostnames (fail-closed).
	addrs, err := g.lookupHost(host)
	if err != nil {
		return &SSRFError{
			URL:    truncateValue(rawURL, 200),
			Reason: "dns_failure",
			Detail: fmt.Sprintf("DNS resolution failed for %s (fail-closed): %s", host, err.Error()),
		}
	}

	for _, addr := range addrs {
		if g.blockedHosts[strings.ToLower(addr)] {
			return &SSRFError{
				URL:    truncateValue(rawURL, 200),
				Reason: "blocked_host",
				Detail: fmt.Sprintf("host %s resolved to blocked address %s", host, addr),
			}
		}
		if ip := net.ParseIP(addr); ip != nil {
			if ssrfErr := g.checkIPForSSRF(ip, host, rawURL); ssrfErr != nil {
				return ssrfErr
			}
		}
	}

	return nil
}

// checkIPForSSRF validates an IP address against blocked CIDRs and private
// network categories. It also extracts embedded IPv4 from IPv6 encoding
// variants (IPv4-compatible, IPv4-translated RFC 2765) that Go's net.IP
// methods do not classify.
func (g *SSRFGuard) checkIPForSSRF(ip net.IP, originalHost, rawURL string) error {
	// Check against explicit CIDR blocklist.
	for _, cidr := range g.blockedCIDRs {
		if cidr.Contains(ip) {
			return &SSRFError{
				URL:    truncateValue(rawURL, 200),
				Reason: "blocked_ip",
				Detail: fmt.Sprintf("IP %s matches blocked CIDR %s (host: %s)", ip, cidr, originalHost),
			}
		}
	}

	if g.blockPrivate {
		// Catch encoding variants not covered by CIDR entries.
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return &SSRFError{
				URL:    truncateValue(rawURL, 200),
				Reason: "private_network",
				Detail: fmt.Sprintf("IP %s is private/loopback/link-local (host: %s)", ip, originalHost),
			}
		}

		// Handle IPv6 encoding variants that embed IPv4 addresses.
		if embeddedErr := g.checkEmbeddedIPv4(ip, originalHost, rawURL); embeddedErr != nil {
			return embeddedErr
		}
	}

	return nil
}

// checkEmbeddedIPv4 extracts IPv4 addresses embedded in IPv6 encoding variants
// and re-checks them against blocked ranges. This prevents SSRF bypasses via:
//   - IPv4-compatible addresses (::x.x.x.x, RFC 4291 §2.5.5.1, deprecated)
//   - IPv4-translated addresses (::ffff:0:x.x.x.x, RFC 2765 §4.2.1)
func (g *SSRFGuard) checkEmbeddedIPv4(ip net.IP, originalHost, rawURL string) error {
	if len(ip) != net.IPv6len || ip.To4() != nil {
		return nil // Not a pure IPv6 address; IPv4-mapped already handled by To4().
	}

	// IPv4-compatible (::x.x.x.x): first 12 bytes are zero.
	if v4 := extractIPv4Compatible(ip); v4 != nil {
		if err := g.checkExtractedV4(v4, ip, "IPv4-compatible", originalHost, rawURL); err != nil {
			return err
		}
	}

	// IPv4-translated (::ffff:0:x.x.x.x, RFC 2765): bytes 8-9 = 0xFFFF, 10-11 = 0x0000.
	if v4 := extractIPv4Translated(ip); v4 != nil {
		if err := g.checkExtractedV4(v4, ip, "IPv4-translated", originalHost, rawURL); err != nil {
			return err
		}
	}

	return nil
}

// checkExtractedV4 validates an extracted IPv4 address against blocked ranges.
func (g *SSRFGuard) checkExtractedV4(v4, original net.IP, variant, host, rawURL string) error {
	for _, cidr := range g.blockedCIDRs {
		if cidr.Contains(v4) {
			return &SSRFError{
				URL:    truncateValue(rawURL, 200),
				Reason: "blocked_ip",
				Detail: fmt.Sprintf("IP %s (%s %s, CIDR %s) for host %s",
					original, variant, v4, cidr, host),
			}
		}
	}
	if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
		return &SSRFError{
			URL:    truncateValue(rawURL, 200),
			Reason: "private_network",
			Detail: fmt.Sprintf("IP %s (%s %s, private/loopback) for host %s",
				original, variant, v4, host),
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// IPv6 embedded IPv4 extraction helpers
// ---------------------------------------------------------------------------

// extractIPv4Compatible extracts the embedded IPv4 from an IPv4-compatible
// IPv6 address (::x.x.x.x — first 12 bytes zero, last 4 non-zero).
func extractIPv4Compatible(ip net.IP) net.IP {
	for i := 0; i < 12; i++ {
		if ip[i] != 0 {
			return nil
		}
	}
	// Must have a non-zero IPv4 portion (exclude ::0.0.0.0 which is unspecified).
	if ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && ip[15] == 0 {
		return nil
	}
	return net.IPv4(ip[12], ip[13], ip[14], ip[15])
}

// extractIPv4Translated extracts the embedded IPv4 from an IPv4-translated
// IPv6 address (::ffff:0:x.x.x.x — RFC 2765 §4.2.1: bytes 0-7 zero,
// bytes 8-9 = 0xFF, bytes 10-11 = 0x00, bytes 12-15 = IPv4).
func extractIPv4Translated(ip net.IP) net.IP {
	// Check prefix: bytes 0-7 must be zero.
	for i := 0; i < 8; i++ {
		if ip[i] != 0 {
			return nil
		}
	}
	// Check marker: bytes 8-9 = 0xFFFF, bytes 10-11 = 0x0000.
	if ip[8] != 0xFF || ip[9] != 0xFF || ip[10] != 0x00 || ip[11] != 0x00 {
		return nil
	}
	// Must have a non-zero IPv4 portion.
	if ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && ip[15] == 0 {
		return nil
	}
	return net.IPv4(ip[12], ip[13], ip[14], ip[15])
}

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

// ssrfMetadataHosts lists well-known cloud metadata service hostnames/IPs.
var ssrfMetadataHosts = []string{
	"169.254.169.254",
	"fd00:ec2::254",
	"metadata.google.internal",
	"100.100.100.200",
}

// ssrfBlockedCIDRs lists CIDR blocks for private, loopback, link-local, and
// IPv6 transition mechanism networks.
var ssrfBlockedCIDRs = []string{
	"0.0.0.0/8",      // "this" network (reaches loopback on Linux/macOS)
	"10.0.0.0/8",     // RFC 1918 private
	"172.16.0.0/12",  // RFC 1918 private
	"192.168.0.0/16", // RFC 1918 private
	"127.0.0.0/8",    // loopback
	"100.64.0.0/10",  // RFC 6598 shared/CGNAT
	"169.254.0.0/16", // IPv4 link-local
	"::1/128",        // IPv6 loopback
	"::/128",         // IPv6 unspecified
	"fc00::/7",       // IPv6 unique local (RFC 4193)
	"fe80::/10",      // IPv6 link-local
	"2002::/16",      // 6to4 relay (deprecated RFC 7526)
	"2001::/32",      // Teredo tunneling (deprecated)
	"64:ff9b::/96",   // NAT64 well-known prefix (RFC 6052)
	"64:ff9b:1::/48", // NAT64 local-use prefix (RFC 8215)
}
