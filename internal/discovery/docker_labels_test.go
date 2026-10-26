package discovery

import (
	"testing"

	"dashgate/internal/models"
)

func TestDockerHomepageLabels(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
		want   *models.App
	}{
		{"homepage route", map[string]string{"homepage.name": "Sonarr", "homepage.href": "https://sonarr.example.test", "homepage.description": "Series", "homepage.group": "Media", "homepage.icon": "sonarr.png", "homepage.widget.key": "secret"}, &models.App{Name: "Sonarr", URL: "https://sonarr.example.test", Description: "Series", Status: "online"}},
		{"explicit DashGate labels win", map[string]string{"dashgate.enable": "true", "dashgate.name": "DashGate", "dashgate.url": "https://dashgate.example.test", "dashgate.groups": "admins", "homepage.name": "Homepage", "homepage.href": "https://homepage.example.test"}, &models.App{Name: "DashGate", URL: "https://dashgate.example.test", Groups: []string{"admins"}, Status: "online"}},
		{"explicit disable wins", map[string]string{"dashgate.enable": "false", "homepage.name": "Sonarr", "homepage.href": "https://sonarr.example.test"}, nil},
		{"incomplete homepage labels", map[string]string{"homepage.name": "Sonarr"}, nil},
		{"invalid homepage scheme", map[string]string{"homepage.name": "Sonarr", "homepage.href": "javascript:alert(1)"}, nil},
		{"homepage URL credentials", map[string]string{"homepage.name": "Sonarr", "homepage.href": "https://user:secret@sonarr.example.test"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dockerContainerApp(models.DockerContainer{Names: []string{"/container"}, State: "running", Labels: tc.labels})
			if tc.want == nil {
				if got != nil {
					t.Fatalf("got %+v, want no app", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got no app, want %+v", *tc.want)
			}
			if got.Name != tc.want.Name || got.URL != tc.want.URL || got.Description != tc.want.Description || got.Icon != tc.want.Icon || got.Status != tc.want.Status || len(got.Groups) != len(tc.want.Groups) {
				t.Fatalf("got %+v, want %+v", *got, *tc.want)
			}
			for i := range tc.want.Groups {
				if got.Groups[i] != tc.want.Groups[i] {
					t.Fatalf("got groups %v, want %v", got.Groups, tc.want.Groups)
				}
			}
		})
	}
}
