package scope

import (
	"os"
	"strings"
	"testing"

	"github.com/nullt3r/massmap/pkg/resolver"
)

// MockDNSResolver implements the Resolver interface for testing
type MockDNSResolver struct {
	mockResponses map[string][]string
}

func NewMockDNSResolver() resolver.Resolver {
	return &MockDNSResolver{
		mockResponses: make(map[string][]string),
	}
}

func (m *MockDNSResolver) LookupIP(domain string) ([]string, error) {
	if ips, ok := m.mockResponses[domain]; ok {
		return ips, nil
	}
	return []string{}, nil
}

func createTempScopeFile(content string) (string, error) {
	tmpfile, err := os.CreateTemp("", "scope_test_*.txt")
	if err != nil {
		return "", err
	}
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		os.Remove(tmpfile.Name())
		return "", err
	}
	if err := tmpfile.Close(); err != nil {
		os.Remove(tmpfile.Name())
		return "", err
	}
	return tmpfile.Name(), nil
}

func TestNewScope(t *testing.T) {
	tests := []struct {
		name        string
		scopeFile   string
		content     string
		wantErr     bool
		expectedLen map[string]int // map of field name to expected length
	}{
		{
			name:      "empty file path",
			scopeFile: "",
			wantErr:   true,
		},
		{
			name: "valid mixed content",
			content: `192.168.1.1
192.168.1.0/24
example.com
# comment line
192.168.2.1
`,
			wantErr: false,
			expectedLen: map[string]int{
				"cidrs":   1,
				"ips":     2,
				"domains": 1,
			},
		},
		{
			name:      "non-existent file",
			scopeFile: "nonexistent.txt",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filename string
			var err error

			if tt.scopeFile == "" && tt.content != "" {
				filename, err = createTempScopeFile(tt.content)
				if err != nil {
					t.Fatalf("failed to create temp file: %v", err)
				}
				defer os.Remove(filename)
			} else {
				filename = tt.scopeFile
			}

			mockResolver := NewMockDNSResolver().(*MockDNSResolver)
			mockResolver.mockResponses = map[string][]string{
				"example.com": {"93.184.216.34"},
			}
			scope, err := NewScope(filename, mockResolver)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewScope() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && scope != nil {
				if len(scope.cidrs) != tt.expectedLen["cidrs"] {
					t.Errorf("NewScope() cidrs length = %v, want %v", len(scope.cidrs), tt.expectedLen["cidrs"])
				}
				if len(scope.ips) != tt.expectedLen["ips"] {
					t.Errorf("NewScope() ips length = %v, want %v", len(scope.ips), tt.expectedLen["ips"])
				}
				if len(scope.domains) != tt.expectedLen["domains"] {
					t.Errorf("NewScope() domains length = %v, want %v", len(scope.domains), tt.expectedLen["domains"])
				}
			}
		})
	}
}

func TestIsInScope(t *testing.T) {
	content := `192.168.1.0/24
10.0.0.1
example.com
test.example.com`

	filename, err := createTempScopeFile(content)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(filename)

	mockResolver := NewMockDNSResolver().(*MockDNSResolver)
	mockResolver.mockResponses = map[string][]string{
		"example.com":      {"93.184.216.34"},
		"test.example.com": {"93.184.216.35"},
		"other.com":        {"8.8.8.8"},
	}
	
	scope, err := NewScope(filename, mockResolver)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	tests := []struct {
		name    string
		target  string
		want    bool
		wantErr bool
	}{
		{
			name:    "IP in CIDR range",
			target:  "192.168.1.100",
			want:    true,
			wantErr: false,
		},
		{
			name:    "IP not in CIDR range",
			target:  "192.168.2.1",
			want:    false,
			wantErr: false,
		},
		{
			name:    "Exact IP match",
			target:  "10.0.0.1",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Domain exact match",
			target:  "example.com",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Domain subdomain match",
			target:  "test.example.com",
			want:    true,
			wantErr: false,
		},
		{
			name:    "Domain not in scope",
			target:  "other.com",
			want:    false,
			wantErr: false,
		},
		{
			name:    "Invalid CIDR",
			target:  "192.168.1.1/33",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scope.IsInScope(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsInScope() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsInScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRejectedCount(t *testing.T) {
	scope := &Scope{}
	
	// Test initial count
	if count := scope.GetRejectedCount(); count != 0 {
		t.Errorf("Initial rejected count = %d, want 0", count)
	}

	// Test after incrementing
	scope.incrementRejected()
	if count := scope.GetRejectedCount(); count != 1 {
		t.Errorf("Rejected count after increment = %d, want 1", count)
	}

	// Test multiple increments
	scope.incrementRejected()
	scope.incrementRejected()
	if count := scope.GetRejectedCount(); count != 3 {
		t.Errorf("Rejected count after multiple increments = %d, want 3", count)
	}
}

func TestCIDROverlap(t *testing.T) {
	tests := []struct {
		name            string
		scopeFile       string
		target          string
		want            bool
		wantErr         bool
		wantScopeErr    bool
		errMessage      string
		scopeErrMessage string
	}{
		{
			name: "Target CIDR larger than scope CIDR",
			scopeFile: `192.168.1.0/24
10.0.0.0/8`,
			target:  "192.168.1.0/23",
			want:    true,
			wantErr: false,
		},
		{
			name: "Target CIDR smaller than scope CIDR",
			scopeFile: `192.168.0.0/23
10.0.0.0/8`,
			target:  "192.168.1.0/24",
			want:    true,
			wantErr: false,
		},
		{
			name: "Non-overlapping CIDRs",
			scopeFile: `192.168.1.0/24
10.0.0.0/8`,
			target:  "192.168.2.0/24",
			want:    false,
			wantErr: false,
		},
		{
			name: "Partially overlapping CIDRs",
			scopeFile: `192.168.1.128/25
10.0.0.0/8`,
			target:  "192.168.1.0/24",
			want:    true,
			wantErr: false,
		},
		{
			name: "Invalid scope CIDR format",
			scopeFile: `192.168.1.256/24
10.0.0.0/8`,
			target:          "192.168.1.0/24",
			want:            false,
			wantScopeErr:    true,
			scopeErrMessage: "invalid scope CIDR",
		},
		{
			name: "Invalid target CIDR format",
			scopeFile: `192.168.1.0/24
10.0.0.0/8`,
			target:     "192.168.1.256/24",
			want:       false,
			wantErr:    true,
			errMessage: "invalid CIDR format",
		},
		{
			name: "Target CIDR matches IP in scope",
			scopeFile: `192.168.1.1
10.0.0.0/8`,
			target:  "192.168.1.0/24",
			want:    true,
			wantErr: false,
		},
		{
			name: "Very specific CIDR ranges",
			scopeFile: `192.168.1.16/28
10.0.0.0/8`,
			target:  "192.168.1.0/24",
			want:    true,
			wantErr: false,
		},
		{
			name: "Exact CIDR match",
			scopeFile: `192.168.1.0/24
10.0.0.0/8`,
			target:  "192.168.1.0/24",
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename, err := createTempScopeFile(tt.scopeFile)
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(filename)

			mockResolver := NewMockDNSResolver()
			scope, err := NewScope(filename, mockResolver)
			if tt.wantScopeErr {
				if err == nil {
					t.Errorf("NewScope() expected error containing %q, got nil", tt.scopeErrMessage)
					return
				}
				if tt.scopeErrMessage != "" && !strings.Contains(err.Error(), tt.scopeErrMessage) {
					t.Errorf("NewScope() error = %v, want error containing %q", err, tt.scopeErrMessage)
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to create scope: %v", err)
			}

			got, err := scope.IsInScope(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("IsInScope() expected error containing %q, got nil", tt.errMessage)
					return
				}
				if tt.errMessage != "" && !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf("IsInScope() error = %v, want error containing %q", err, tt.errMessage)
				}
				return
			}
			if err != nil {
				t.Errorf("IsInScope() unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("IsInScope() = %v, want %v", got, tt.want)
			}
		})
	}
}
