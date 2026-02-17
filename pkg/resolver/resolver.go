package resolver

// Resolver is the interface that wraps the basic DNS lookup methods
type Resolver interface {
	LookupIP(domain string) ([]string, error)
}
