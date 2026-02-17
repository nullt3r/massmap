package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/nullt3r/massmap/pkg/nmapxml"
	"github.com/nullt3r/massmap/pkg/utils"
)

type Finding struct {
	Host    string
	Domains []string
	Ports   []string
	Details nmapxml.NmapXML
}

type FindingsManager struct {
	Storage *[]Finding
	Mutex   *sync.RWMutex
}

func NewFindingsManager() *FindingsManager {
	findings := make([]Finding, 0)
	return &FindingsManager{
		Storage: &findings,
		Mutex:   &sync.RWMutex{},
	}
}

func (f *FindingsManager) HostExists(host string) bool {
	f.Mutex.RLock()
	defer f.Mutex.RUnlock()
	
	for i := range *f.Storage {
		if (*f.Storage)[i].Host == host {
			return true
		}
	}
	return false
}

func (f *FindingsManager) AddHost(host string, ports []string, domains []string) {
	f.Mutex.Lock()
	defer f.Mutex.Unlock()

	for i := range *f.Storage {
		if (*f.Storage)[i].Host == host {
			// Update existing host
			(*f.Storage)[i].Ports = append((*f.Storage)[i].Ports, ports...)
			if len(domains) > 0 {
				(*f.Storage)[i].Domains = append((*f.Storage)[i].Domains, domains...)
			}
			return
		}
	}

	// Add new host
	*f.Storage = append(*f.Storage, Finding{
		Host:    host,
		Ports:   ports,
		Domains: domains,
	})
}

func (f *FindingsManager) SaveEverythingToFile(filename string) error {
	if filename == "" {
		return fmt.Errorf("no filename provided")
	}

	// Create temporary file
	tmpFile := filename + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer file.Close()

	f.Mutex.RLock()
	defer f.Mutex.RUnlock()

	for _, r := range *f.Storage {
		b, err := json.MarshalIndent(r, "", "    ")
		if err != nil {
			return fmt.Errorf("failed to marshal finding: %w", err)
		}
		if _, err := file.WriteString(string(b) + "\n"); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	// Ensure all data is written to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Atomically rename temporary file
	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile) // Clean up temp file if rename fails
		return fmt.Errorf("failed to save file: %w", err)
	}

	return nil
}

func (f *FindingsManager) SaveHostPortToFile(filename string) error {
	if filename == "" {
		return fmt.Errorf("no filename provided")
	}

	tmpFile := filename + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer file.Close()

	f.Mutex.RLock()
	defer f.Mutex.RUnlock()

	for _, finding := range *f.Storage {
		if len(finding.Ports) == 0 {
			continue
		}

		for _, port := range finding.Ports {
			if len(finding.Domains) != 0 {
				for _, domain := range finding.Domains {
					if _, err := file.WriteString(fmt.Sprintf("%s:%s\n", domain, port)); err != nil {
						return fmt.Errorf("failed to write domain:port to file: %w", err)
					}
				}
			}

			host := finding.Host
			if utils.IsIPv6(host) {
				host = "[" + host + "]"
			}
			if _, err := file.WriteString(fmt.Sprintf("%s:%s\n", host, port)); err != nil {
				return fmt.Errorf("failed to write host:port to file: %w", err)
			}
		}
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("failed to save file: %w", err)
	}

	return nil
}
