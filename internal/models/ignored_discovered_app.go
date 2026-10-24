package models

// IgnoredDiscoveredApp is an inbox dismissal keyed by discovery source and URL.
type IgnoredDiscoveredApp struct {
	Source    string `json:"source"`
	URL       string `json:"url"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}
