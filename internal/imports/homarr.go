package imports

import (
	"encoding/json"
	"strings"
)

type homarrConfig struct {
	Apps []homarrApp `json:"apps"`
}

type homarrApp struct {
	Name   string         `json:"name"`
	URL    string         `json:"url"`
	Behaviour homarrBehaviour `json:"behaviour"`
	Appearance homarrAppearance `json:"appearance"`
}

type homarrBehaviour struct {
	ExternalURL string `json:"externalUrl"`
}

type homarrAppearance struct {
	IconURL string `json:"iconUrl"`
}

func ParseHomarr(content string) (*ImportResult, error) {
	result := &ImportResult{Source: SourceHomarr}

	var cfg homarrConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, err
	}

	for _, a := range cfg.Apps {
		if a.Name == "" {
			continue
		}

		url := a.URL
		if a.Behaviour.ExternalURL != "" {
			url = a.Behaviour.ExternalURL
		}
		if url == "" {
			continue
		}

		app := ImportedApp{
			Name:        a.Name,
			URL:         url,
			Category:    "Imported",
		}

		if a.Appearance.IconURL != "" {
			app.Icon = a.Appearance.IconURL
			if strings.HasPrefix(a.Appearance.IconURL, "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons") {
				result.Warnings = append(result.Warnings, "icon for '"+a.Name+"' is a remote CDN URL; DashGate will use it as-is but consider using local icons")
			}
		}

		result.Apps = append(result.Apps, app)
	}

	return result, nil
}
