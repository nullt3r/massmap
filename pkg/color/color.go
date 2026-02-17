package color

import (
	"runtime"
	"strings"
	"sync"
)

type colors struct {
	Gray   string
	Cyan   string
	Yellow string
	Green  string
	Purple string
	Red    string
	Reset  string
}

var (
	instance *colors
	once     sync.Once
)

// SetColor returns a singleton instance of colors with proper initialization
func SetColor() *colors {
	once.Do(func() {
		instance = &colors{}
		if runtime.GOOS == "windows" {
			instance.Gray = ""
			instance.Cyan = ""
			instance.Yellow = ""
			instance.Green = ""
			instance.Purple = ""
			instance.Red = ""
			instance.Reset = ""
		} else {
			instance.Gray = "\033[1;30m"
			instance.Cyan = "\033[36m"
			instance.Yellow = "\033[33m"
			instance.Green = "\033[32m"
			instance.Purple = "\033[0;35m"
			instance.Red = "\033[1;31m"
			instance.Reset = "\033[0m"
		}
	})
	return instance
}

// IsColorSupported returns whether the current environment supports color output
func IsColorSupported() bool {
	return runtime.GOOS != "windows"
}

// StripColors removes all color codes from a string
func StripColors(s string) string {
	result := s

	// Match any ANSI escape sequence: \x1b[...m or \033[...m
	for {
		start := -1
		if strings.Contains(result, "\x1b[") {
			start = strings.Index(result, "\x1b[")
		} else if strings.Contains(result, "\033[") {
			start = strings.Index(result, "\033[")
		}

		if start == -1 {
			break
		}

		// Find the end of the sequence (marked by 'm')
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}

		result = result[:start] + result[start+end+1:]
	}

	// Also handle any raw escape characters that might remain
	result = strings.ReplaceAll(result, "\x1b", "")
	result = strings.ReplaceAll(result, "\033", "")

	return result
}
