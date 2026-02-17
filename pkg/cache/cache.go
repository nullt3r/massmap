package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/nullt3r/massmap/pkg/scanner"
)

type Ports struct {
	Path     string
	Findings *[]scanner.Finding
}

func Initialize(path string, findings *[]scanner.Finding) (*Ports, error) {
	fileInfo, err := os.Stat(path)

	if os.IsNotExist(err) {
		f, err := os.Create(path)

		if err != nil {
			return nil, fmt.Errorf("there was an error creating cache file: %s", err)
		}

		defer f.Close()

		return &Ports{
			Path:     path,
			Findings: findings,
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("there was an error accessing cache file: %s", err)
	}

	if fileInfo.IsDir() {
		return nil, fmt.Errorf("'%s' is a directory, not a file", path)
	}

	return &Ports{
		Path:     path,
		Findings: findings,
	}, nil
}

func (f *Ports) getStats() map[string]int {
	stats := make(map[string]int)

	for _, v := range *f.Findings {
		for _, p := range v.Ports {
			stats[p] += 1
		}
	}

	return stats
}

func (portCache *Ports) PrintStats() error {
	stats, err := portCache.ReadCache()
	counter := 0

	type keyCount struct {
		key   string
		count int
	}
	var kcSlice []keyCount
	for k, v := range stats {
		kcSlice = append(kcSlice, keyCount{k, v})
	}

	// Sort the slice based on the count
	sort.Slice(kcSlice, func(i, j int) bool {
		return kcSlice[i].count > kcSlice[j].count
	})

	if err != nil {
		return fmt.Errorf("warning, could not get ports from the cache: %s", err)
	}

	fmt.Println("Port statistics:")
	fmt.Println()

	// Modified this line to only show "consider pruning cache" when appropriate
	pruneMessage := ""
	if len(kcSlice) > 10000 {
		pruneMessage = " (consider pruning cache)"
	}
	fmt.Printf(" Cache size: %d ports%s\n", len(kcSlice), pruneMessage)
	fmt.Printf(" Cache file: %s\n\n", portCache.Path)

	fmt.Println(" Top 100 ports:")
	fmt.Println()
	fmt.Println("  Port\tCount")

	for _, val := range kcSlice {
		if counter == 100 {
			break
		}
		fmt.Printf("  %s\t%d\n", val.key, val.count)
		counter += 1
	}

	return nil
}

func (portCache *Ports) GetAll() ([]string, error) {
	stats, err := portCache.ReadCache()
	if err != nil {
		return nil, fmt.Errorf("warning, could not get ports from the cache: %s", err)
	}

	type keyCount struct {
		key   string
		count int
	}
	var kcSlice []keyCount
	for k, v := range stats {
		kcSlice = append(kcSlice, keyCount{k, v})
	}

	// Sort the slice based on the count
	sort.Slice(kcSlice, func(i, j int) bool {
		return kcSlice[i].count > kcSlice[j].count
	})

	// Collect unique keys
	uniqueKeys := make(map[string]bool)
	var result []string
	for _, kc := range kcSlice {
		if !uniqueKeys[kc.key] {
			uniqueKeys[kc.key] = true
			result = append(result, kc.key)
		}
	}
	return result, nil
}

func (portCache *Ports) GetTop(count int) ([]string, error) {
	stats, err := portCache.ReadCache()
	if err != nil {
		return nil, fmt.Errorf("warning, could not get ports from the cache: %s", err)
	}

	type keyCount struct {
		key   string
		count int
	}
	var kcSlice []keyCount
	for k, v := range stats {
		kcSlice = append(kcSlice, keyCount{k, v})
	}

	// Sort the slice based on the count
	sort.Slice(kcSlice, func(i, j int) bool {
		return kcSlice[i].count > kcSlice[j].count
	})

	// Collect unique keys
	uniqueKeys := make(map[string]bool)
	var result []string
	for _, kc := range kcSlice {
		if !uniqueKeys[kc.key] {
			uniqueKeys[kc.key] = true
			result = append(result, kc.key)
		}
	}

	if count <= 0 || len(result) == 0 {
		return []string{}, nil
	}

	if count > len(result) {
		return result, nil
	}

	return result[:count], nil

}

func (portCache *Ports) WriteCache() error {
	filename := portCache.Path

	data := portCache.getStats()

	fileInfo, err := os.Stat(filename)
	if err == nil {
		if fileInfo.Size() != 0 {
			// If it exists and is empty, load its contents
			existingData, err := portCache.ReadCache()
			if err != nil {
				return fmt.Errorf("cache file could not be loaded: %w", err)
			}

			if len(existingData) != 0 {
				// Add new values to existing keys
				for k, v := range data {
					existingData[k] += v
				}

				data = existingData

			}
		}

	}

	// Encode the data to JSON format
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to encode data to JSON: %w", err)
	}

	// Save the data to the file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to save data to cache file: %w", err)
	}

	return nil
}

func (portCache *Ports) ReadCache() (map[string]int, error) {
	if portCache.Path == "" {
		return nil, fmt.Errorf("no cache file path specified")
	}

	data := make(map[string]int)

	fileInfo, err := os.Stat(portCache.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil // Return empty map if file doesn't exist
		}
		return nil, fmt.Errorf("failed to stat cache file: %w", err)
	}

	if fileInfo.Size() == 0 {
		return data, nil // Return empty map for empty file
	}

	jsonData, err := os.ReadFile(portCache.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to decode data from cache file: %w", err)
	}

	return data, nil
}

func (portCache *Ports) SaveCache() error {
	if portCache.Path == "" {
		return fmt.Errorf("no cache file path specified")
	}

	stats := portCache.getStats()
	if len(stats) == 0 {
		return nil // Nothing to save
	}

	jsonData, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode data to JSON: %w", err)
	}

	// Write to temporary file first
	tmpFile := portCache.Path + ".tmp"
	if err := os.WriteFile(tmpFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write temporary cache file: %w", err)
	}

	// Atomically rename temporary file to target file
	if err := os.Rename(tmpFile, portCache.Path); err != nil {
		os.Remove(tmpFile) // Clean up temp file if rename fails
		return fmt.Errorf("failed to save cache file: %w", err)
	}

	return nil
}

func (portCache *Ports) PruneCache(level int) (int, error) {
	if level < 0 {
		return 0, fmt.Errorf("invalid prune level: %d", level)
	}

	data, err := portCache.ReadCache()
	if err != nil {
		return 0, fmt.Errorf("failed to read cache: %w", err)
	}

	removedCounter := 0
	for key, count := range data {
		if count <= level {
			delete(data, key)
			removedCounter++
		}
	}

	if removedCounter > 0 {
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return 0, fmt.Errorf("failed to encode pruned data: %w", err)
		}

		if err := os.WriteFile(portCache.Path, jsonData, 0644); err != nil {
			return 0, fmt.Errorf("failed to write pruned cache: %w", err)
		}
	}

	return removedCounter, nil
}

func (portCache *Ports) FlushCache() error {
	if portCache.Path == "" {
		return fmt.Errorf("no cache file path specified")
	}

	err := os.Remove(portCache.Path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}
	return nil
}

func (portCache *Ports) GetCacheStats() string {
	stats, err := portCache.ReadCache()
	if err != nil {
		return fmt.Sprintf("Error reading cache: %v", err)
	}

	cacheSize := len(stats)
	result := fmt.Sprintf("Cache contains %d ports", cacheSize)

	if cacheSize > 10000 {
		result += "\nConsider pruning cache"
	}

	return result
}
