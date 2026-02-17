package scanner

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/nullt3r/massmap/pkg/resolver"
	"github.com/nullt3r/massmap/pkg/scope"
	"github.com/nullt3r/massmap/pkg/utils"
)

type TargetLoader struct {
	UserTargets    *[]string
	FinalTargets   *[]string
	ExcludedHosts  *[]string
	Findings       *[]Finding
	ResolversFile  string
	IPv6Enabled    bool
	DNSConcurrency int
	Logger         *log.Logger
	ScopeFile      string
}

func (TL *TargetLoader) HostExists(host string) bool {
	for i := range *TL.Findings {
		if (*TL.Findings)[i].Host == host {
			return true
		}
	}
	return false
}

func (TL *TargetLoader) loadIP(ip *string, lock *sync.Mutex, scopeChecker *scope.Scope) error {
	untrustedTarget := *ip
	var rejectedCount int

	if utils.IsCIDR(untrustedTarget) {
		untrustedIPs, err := utils.CIDRtoIPs(untrustedTarget)
		if err != nil {
			return fmt.Errorf("error while processing CIDR: %s", err)
		}

		for _, uIP := range untrustedIPs {
			ipStr := uIP.String()
			
			// Check exclusions
			excluded := false
			if len(*TL.ExcludedHosts) > 0 {
				for _, excludedHost := range *TL.ExcludedHosts {
					if ipStr == excludedHost {
						excluded = true
						TL.Logger.Printf("\033[33mIP '%s' is excluded, skipping\033[0m", ipStr)
						rejectedCount++
						break
					}
				}
			}
			if excluded {
				continue
			}

			// Check scope if enabled
			if scopeChecker != nil {
				inScope, err := scopeChecker.IsInScope(ipStr)
				if err != nil {
					TL.Logger.Printf("\033[31merror checking scope for IP '%s': %s\033[0m", ipStr, err)
					continue
				}
				if !inScope {
					TL.Logger.Printf("\033[33mIP '%s' is not in scope, skipping\033[0m", ipStr)
					rejectedCount++
					continue
				}
			}

			lock.Lock()
			if !utils.Contains((*TL.FinalTargets), ipStr) {
				(*TL.FinalTargets) = append((*TL.FinalTargets), ipStr)
			}
			lock.Unlock()
		}
	} else {
		// Check exclusions
		if len(*TL.ExcludedHosts) > 0 {
			for _, excludedHost := range *TL.ExcludedHosts {
				if untrustedTarget == excludedHost {
					TL.Logger.Printf("\033[33mIP '%s' is excluded, skipping\033[0m", untrustedTarget)
					rejectedCount++
					return nil
				}
			}
		}

		// Check scope if enabled
		if scopeChecker != nil {
			inScope, err := scopeChecker.IsInScope(untrustedTarget)
			if err != nil {
				return fmt.Errorf("\033[31merror checking scope for IP '%s': %s\033[0m", untrustedTarget, err)
			}
			if !inScope {
				TL.Logger.Printf("\033[33mIP '%s' is not in scope, skipping\033[0m", untrustedTarget)
				rejectedCount++
				return nil
			}
		}

		lock.Lock()
		if !utils.Contains((*TL.FinalTargets), untrustedTarget) {
			(*TL.FinalTargets) = append((*TL.FinalTargets), untrustedTarget)
		}
		lock.Unlock()
	}

	if rejectedCount > 0 {
		lock.Lock()
		TL.Logger.Printf("\033[33m%d IPs were rejected due to scope restrictions\033[0m", rejectedCount)
		lock.Unlock()
	}

	return nil
}

func (TL *TargetLoader) Load() {
	var wg sync.WaitGroup
	var lock sync.Mutex
	var resolvers []string
	var rejectedCount int

	logger := TL.Logger

	if TL.ResolversFile != "" {
		r, err := utils.ReadFile(TL.ResolversFile)
		if err != nil {
			logger.Fatalf("\033[31mproblem loading resolvers from file: %s\033[0m", err)
		}
		resolvers = r
	} else {
		resolvers = []string{"1.0.0.1", "1.1.1.1", "1.1.1.2", "1.1.1.3", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "185.228.168.9", "185.228.169.9", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", "8.26.56.26", "8.20.247.20", "185.228.169.168", "64.6.64.6", "64.6.65.6", "77.88.8.8", "77.88.8.1", "77.88.8.88", "77.88.8.2", "77.88.8.7", "77.88.8.3", "209.244.0.3", "209.244.0.4", "216.146.35.35", "216.146.36.36", "156.154.70.5"}
		logger.Printf("\033[33musing internal resolvers, consider providing your own using '-r' flag\033[0m")
	}

	dns := resolver.DNSResolver{
		Resolvers: resolvers,
	}

	var scopeChecker *scope.Scope
	if TL.ScopeFile != "" {
		var err error
		scopeChecker, err = scope.NewScope(TL.ScopeFile, &dns)
		if err != nil {
			logger.Fatalf("\033[31mfailed to initialize scope checker: %s\033[0m", err)
		}
		logger.Printf("scope file loaded successfully")
	}

	guard := make(chan struct{}, TL.DNSConcurrency)

	for _, untrustedTarget := range *TL.UserTargets {
		wg.Add(1)

		guard <- struct{}{}

		go func(untrustedTarget string) {
			defer wg.Done()

			defer func() {
				<-guard
			}()

			if utils.IsIPv6(untrustedTarget) && !TL.IPv6Enabled {
				logger.Printf("\033[33mtarget is IPv6 address but -6 is not present, skipping: %s\033[0m", untrustedTarget)
				return
			}

			_, _, err := net.ParseCIDR(untrustedTarget)

			if err != nil && net.ParseIP(untrustedTarget) == nil {
				// For domains, resolve first to check both domain and IPs against scope
				ips, err := dns.LookupIP(untrustedTarget)
				if err != nil {
					logger.Printf("\033[31merror resolving domain '%s': %s\033[0m", untrustedTarget, err)
					return
				}

				if len(ips) == 0 {
					logger.Printf("\033[31merror resolving domain '%s', maybe bad resolvers?\033[0m", untrustedTarget)
					return
				}

				domain := untrustedTarget
				logger.Printf("%s -> %s", domain, ips)

				// If scope checking is enabled, determine which IPs are in scope
				var scopedIPs []string
				if scopeChecker != nil {
					domainInScope, err := scopeChecker.IsInScope(domain)
					if err != nil {
						logger.Printf("\033[31merror checking scope for domain '%s': %s\033[0m", domain, err)
						return
					}

					if domainInScope {
						// If domain is in scope, include all its IPs
						for _, ip := range ips {
							scopedIPs = append(scopedIPs, ip)
						}
					} else {
						// If domain is not in scope, check each IP
						for _, ip := range ips {
							inScope, err := scopeChecker.IsInScope(ip)
							if err != nil {
								logger.Printf("\033[31merror checking scope for IP '%s': %s\033[0m", ip, err)
								continue
							}
							if inScope {
								scopedIPs = append(scopedIPs, ip)
							} else {
								logger.Printf("\033[33mIP '%s' from domain '%s' is not in scope, skipping\033[0m", ip, domain)
								lock.Lock()
								rejectedCount++
								lock.Unlock()
							}
						}
						if len(scopedIPs) == 0 {
							logger.Printf("\033[33mneither domain '%s' nor its IPs are in scope, skipping\033[0m", domain)
							return
						}
					}
				} else {
					// If no scope checking, include all IPs
					for _, ip := range ips {
						scopedIPs = append(scopedIPs, ip)
					}
				}

				// Process only the IPs that are in scope
				for _, ip := range scopedIPs {
					if utils.IsIPv6(ip) && !TL.IPv6Enabled {
						logger.Printf("\033[33mtarget is IPv6 address but -6 is not present, skipping: %s (%s)\033[0m", ip, domain)
						continue
					}

					err := TL.loadIP(&ip, &lock, nil) // Skip scope check as we've already validated
					if err != nil {
						logger.Fatal(err)
					}

					lock.Lock()
					if TL.HostExists(ip) {
						for i := range *TL.Findings {
							if (*TL.Findings)[i].Host == ip {
								(*TL.Findings)[i].Domains = append((*TL.Findings)[i].Domains, domain)
							}
						}
					} else {
						(*TL.Findings) = append((*TL.Findings), Finding{Host: ip, Domains: []string{domain}})
					}
					lock.Unlock()
				}
			} else {
				err := TL.loadIP(&untrustedTarget, &lock, scopeChecker)
				if err != nil {
					logger.Fatal(err)
				}
			}

		}(untrustedTarget)
	}

	wg.Wait()

	if scopeChecker != nil && rejectedCount > 0 {
		logger.Printf("\033[33m%d IPs were rejected due to scope restrictions\033[0m", rejectedCount)
	}
}
