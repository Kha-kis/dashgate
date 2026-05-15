package imports

import (
	"strings"

	"gopkg.in/yaml.v3"
)

func ParseHomepage(content string) (*ImportResult, error) {
	result := &ImportResult{Source: SourceHomepage}

	var groups []yaml.Node
	if err := yaml.Unmarshal([]byte(content), &groups); err != nil {
		return nil, err
	}

	for _, group := range groups {
		if group.Kind != yaml.MappingNode || len(group.Content) < 2 {
			continue
		}

		var groupName string
		if err := group.Content[0].Decode(&groupName); err != nil {
			continue
		}

		servicesNode := group.Content[1]
		if servicesNode.Kind != yaml.SequenceNode {
			continue
		}

		for _, svc := range servicesNode.Content {
			if svc.Kind != yaml.MappingNode || len(svc.Content) < 2 {
				continue
			}

			var svcName string
			if err := svc.Content[0].Decode(&svcName); err != nil {
				continue
			}

			var svcProps map[string]interface{}
			if err := svc.Content[1].Decode(&svcProps); err != nil {
				continue
			}

			url := stringProp(svcProps, "href")
			if url == "" {
				url = stringProp(svcProps, "server")
			}
			if url == "" {
				continue
			}

			app := ImportedApp{
				Name:        svcName,
				URL:         url,
				Description: stringProp(svcProps, "description"),
				Category:    groupName,
			}

			if icon, ok := svcProps["icon"].(string); ok {
				app.Icon = icon
				if !strings.HasPrefix(icon, "http://") && !strings.HasPrefix(icon, "https://") {
					result.Warnings = append(result.Warnings, "icon '"+icon+"' for '"+svcName+"' is a relative path; DashGate only supports URLs or built-in icons")
				}
			}

			result.Apps = append(result.Apps, app)
		}
	}

	return result, nil
}
