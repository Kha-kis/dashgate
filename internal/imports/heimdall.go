package imports

import (
	"encoding/json"
	"strings"
)

type heimdallItem struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Colour      string `json:"colour"`
	Icon        string `json:"icon"`
	Description string `json:"appdescription"`
	Type        int    `json:"type"`
}

func ParseHeimdall(content string) (*ImportResult, error) {
	result := &ImportResult{Source: SourceHeimdall}

	var items []heimdallItem
	if err := json.Unmarshal([]byte(content), &items); err != nil {
		return nil, err
	}

	for _, item := range items {
		if item.Type != 0 {
			continue
		}
		if item.Title == "" || item.URL == "" {
			continue
		}

		app := ImportedApp{
			Name:        item.Title,
			URL:         item.URL,
			Description: item.Description,
			Category:    "Imported",
		}

		if item.Icon != "" {
			if !strings.HasPrefix(item.Icon, "http://") && !strings.HasPrefix(item.Icon, "https://") {
				result.Warnings = append(result.Warnings, "icon '"+item.Icon+"' for '"+item.Title+"' is not an absolute URL; DashGate only supports URL icons or built-in icons")
			} else {
				app.Icon = item.Icon
			}
		}

		result.Apps = append(result.Apps, app)
	}

	return result, nil
}
