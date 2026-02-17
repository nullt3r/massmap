package scope

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/nullt3r/massmap/pkg/resolver"
	"github.com/nullt3r/massmap/pkg/utils"
)

type Scope struct {
	cidrs   []string
	ips     []string
	domains []string
	dnsResolver resolver.Resolver
	rejected    uint64 // Counter for rejected IPs
}

// GetRejectedCount returns the number of IPs rejected due to scope
func (s *Scope) GetRejectedCount() uint64 {
	return atomic.LoadUint64(&s.rejected)
}

// incrementRejected increments the rejected counter
func (s *Scope) incrementRejected() {
	atomic.AddUint64(&s.rejected, 1)
}

// NewScope creates a new scope checker from a scope file
func NewScope(scopeFile string, r resolver.Resolver) (*Scope, error) {
	if scopeFile == "" {
		return nil, fmt.Errorf("scope file is required")
	}

	s := &Scope{
		dnsResolver: r,
	}

	file, err := os.Open(scopeFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open scope file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a CIDR
		if strings.Contains(line, "/") {
			_, _, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("invalid scope CIDR %s: %v", line, err)
			}
			s.cidrs = append(s.cidrs, line)
			continue
		}

		// Check if it's an IP
		if utils.IsIP(line) {
			s.ips = append(s.ips, line)
			continue
		}

		// Assume it's a domain if not IP or CIDR
		s.domains = append(s.domains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading scope file: %v", err)
	}

	return s, nil
}

// IsInScope checks if a target (IP, CIDR, or domain) is within the defined scope
func (s *Scope) IsInScope(target string) (bool, error) {
	// Check if target is a CIDR
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		if err != nil {
			return false, fmt.Errorf("invalid CIDR format: %v", err)
		}
		return s.isCIDRInScope(target)
	}

	// Check if target is an IP
	if utils.IsIP(target) {
		return s.isIPInScope(target), nil
	}

	// Assume it's a domain if not IP or CIDR
	return s.isDomainInScope(target)
}

// isCIDRInScope checks if any part of the given CIDR is within scope
// Returns true if any part of the CIDR is in scope, and the error if any
func (s *Scope) isCIDRInScope(cidr string) (bool, error) {
	targetIP, targetNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid target CIDR: %v", err)
	}

	// For each scope CIDR, check if there's any overlap
	for _, scopeCIDR := range s.cidrs {
		_, scopeNet, err := net.ParseCIDR(scopeCIDR)
		if err != nil {
			return false, fmt.Errorf("invalid scope CIDR %s: %v", scopeCIDR, err)
		}

		// If the scope network contains any part of the target network, it's in scope
		if scopeNet.Contains(targetIP) {
			return true, nil
		}

		// Also check if target network contains the scope network's IP
		scopeIP, _, _ := net.ParseCIDR(scopeCIDR)
		if targetNet.Contains(scopeIP) {
			return true, nil
		}
	}

	// If no scope CIDR overlaps, check individual IPs
	for _, scopeIP := range s.ips {
		if utils.IPinCIDR(scopeIP, cidr) {
			return true, nil
		}
	}

	return false, nil
}

// isIPInScope checks if the given IP is within any scope CIDRs or matches any scope IPs
func (s *Scope) isIPInScope(ip string) bool {
	// Check if IP matches any scope IPs
	for _, scopeIP := range s.ips {
		if ip == scopeIP {
			return true
		}
	}

	// Check if IP is in any scope CIDRs
	for _, cidr := range s.cidrs {
		if utils.IPinCIDR(ip, cidr) {
			return true
		}
	}

	s.incrementRejected()
	return false
}

// isDomainInScope resolves the domain and checks if any of its IPs are in scope
func (s *Scope) isDomainInScope(domain string) (bool, error) {
	// First check if domain exactly matches any scope domains
	for _, scopeDomain := range s.domains {
		if strings.EqualFold(domain, scopeDomain) {
			return true, nil
		}
		// Check if domain is a subdomain of any scope domain
		if strings.HasSuffix(domain, "."+scopeDomain) {
			return true, nil
		}
	}

	// If domain isn't directly in scope, resolve it and check its IPs
	ips, err := s.dnsResolver.LookupIP(domain)
	if err != nil {
		return false, fmt.Errorf("failed to resolve domain %s: %v", domain, err)
	}

	for _, ip := range ips {
		if s.isIPInScope(ip) {
			return true, nil
		}
	}

	return false, nil
}
