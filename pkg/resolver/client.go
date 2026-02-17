package resolver

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

type DNSResolver struct {
	Resolvers []string
}

func init() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())
}

func (d *DNSResolver) LookupIP(domain string) ([]string, error) {
	var ips []string

	c := dns.Client{
		Timeout: 5 * time.Second,
	}
	m := dns.Msg{}

	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	if err := d.attemptDNSExchange(&c, &m, &ips); err != nil {
		return nil, fmt.Errorf("A record lookup failed: %v", err)
	}

	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	if err := d.attemptDNSExchange(&c, &m, &ips); err != nil {
		// Don't fail if AAAA lookup fails, just log it
		return ips, nil
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for domain: %s", domain)
	}

	return ips, nil
}

func (d *DNSResolver) attemptDNSExchange(c *dns.Client, m *dns.Msg, ips *[]string) error {
	var lastErr error
	resolvers := make([]string, len(d.Resolvers))
	copy(resolvers, d.Resolvers)
	rand.Shuffle(len(resolvers), func(i, j int) {
		resolvers[i], resolvers[j] = resolvers[j], resolvers[i]
	})

	for i := 0; i < 3; i++ { // Reduced retry count and using shuffled resolvers
		for _, resolver := range resolvers {
			r, _, err := c.Exchange(m, resolver+":53")
			if err != nil {
				lastErr = fmt.Errorf("resolver %s failed: %v", resolver, err)
				continue
			}
			if r.Rcode != dns.RcodeSuccess {
				lastErr = fmt.Errorf("resolver %s returned non-success code: %v", resolver, r.Rcode)
				continue
			}
			
			for _, ans := range r.Answer {
				if a, ok := ans.(*dns.A); ok {
					*ips = append(*ips, a.A.String())
				} else if aaaa, ok := ans.(*dns.AAAA); ok {
					*ips = append(*ips, aaaa.AAAA.String())
				}
			}
			if len(*ips) > 0 {
				return nil
			}
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	
	if lastErr != nil {
		return fmt.Errorf("all DNS resolution attempts failed, last error: %v", lastErr)
	}
	return fmt.Errorf("no DNS records found")
}
