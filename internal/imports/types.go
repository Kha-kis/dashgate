package imports

type SourceType string

const (
	SourceHomepage SourceType = "homepage"
	SourceHomarr   SourceType = "homarr"
	SourceHeimdall SourceType = "heimdall"
)

type ImportedApp struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Icon        string `json:"icon"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

type ImportResult struct {
	Source   SourceType     `json:"source"`
	Apps     []ImportedApp  `json:"apps"`
	Errors   []string       `json:"errors,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

type ImportRequest struct {
	Source   SourceType `json:"source"`
	Content  string     `json:"content"`
}
