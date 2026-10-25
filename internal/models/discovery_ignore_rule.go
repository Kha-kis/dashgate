package models

// DiscoveryIgnoreRule removes matching actionable routes from the admin inbox.
// It does not affect dashboard publication or access.
type DiscoveryIgnoreRule struct {
	ID         int64  `json:"id"`
	Source     string `json:"source"`
	Origin     string `json:"origin"`
	PathPrefix string `json:"pathPrefix"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

type DiscoveryRuleMatch struct {
	Source string `json:"source"`
	URL    string `json:"url"`
	RuleID int64  `json:"ruleId"`
}
