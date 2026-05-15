package imports

import (
	"testing"
)

func TestParseHomepage(t *testing.T) {
	content := `- Media:
    - Plex:
        href: http://plex:32400
        description: Media server
    - Radarr:
        href: http://radarr:7878
        icon: https://example.com/radarr.png

- Admin:
    - Portainer:
        href: https://portainer.local
        description: Docker management
`

	result, err := ParseHomepage(content)
	if err != nil {
		t.Fatalf("ParseHomepage returned error: %v", err)
	}

	if len(result.Apps) != 3 {
		t.Errorf("expected 3 apps, got %d", len(result.Apps))
	}

	if result.Apps[0].Name != "Plex" {
		t.Errorf("expected first app 'Plex', got '%s'", result.Apps[0].Name)
	}
	if result.Apps[0].Category != "Media" {
		t.Errorf("expected category 'Media', got '%s'", result.Apps[0].Category)
	}
	if result.Apps[1].Icon != "https://example.com/radarr.png" {
		t.Errorf("expected icon URL, got '%s'", result.Apps[1].Icon)
	}
}

func TestParseHomarr(t *testing.T) {
	content := `{
  "apps": [
    {
      "name": "Plex",
      "url": "http://plex:32400",
      "behaviour": {"externalUrl": ""},
      "appearance": {"iconUrl": "https://example.com/plex.png"}
    },
    {
      "name": "Sonarr",
      "url": "",
      "behaviour": {"externalUrl": "http://sonarr:8989"},
      "appearance": {"iconUrl": ""}
    }
  ]
}`

	result, err := ParseHomarr(content)
	if err != nil {
		t.Fatalf("ParseHomarr returned error: %v", err)
	}

	if len(result.Apps) != 2 {
		t.Errorf("expected 2 apps, got %d", len(result.Apps))
	}
	if result.Apps[0].Name != "Plex" {
		t.Errorf("expected 'Plex', got '%s'", result.Apps[0].Name)
	}
	if result.Apps[0].URL != "http://plex:32400" {
		t.Errorf("expected Plex URL, got '%s'", result.Apps[0].URL)
	}
	if result.Apps[1].URL != "http://sonarr:8989" {
		t.Errorf("expected Sonarr URL from externalUrl, got '%s'", result.Apps[1].URL)
	}
}

func TestParseHeimdall(t *testing.T) {
	content := `[
  {"title": "Plex", "url": "http://plex:32400", "icon": "https://example.com/plex.png", "type": 0},
  {"title": "Movies", "url": "tag/movies", "type": 1},
  {"title": "Sonarr", "url": "http://sonarr:8989", "type": 0, "icon": ""}
]`

	result, err := ParseHeimdall(content)
	if err != nil {
		t.Fatalf("ParseHeimdall returned error: %v", err)
	}

	if len(result.Apps) != 2 {
		t.Errorf("expected 2 apps (type=1 should be skipped), got %d", len(result.Apps))
	}
	if result.Apps[0].Name != "Plex" {
		t.Errorf("expected 'Plex', got '%s'", result.Apps[0].Name)
	}
	if result.Apps[1].Name != "Sonarr" {
		t.Errorf("expected 'Sonarr', got '%s'", result.Apps[1].Name)
	}
}

func TestParseHomepageEmpty(t *testing.T) {
	result, err := ParseHomepage("[]")
	if err != nil {
		t.Fatalf("ParseHomepage empty returned error: %v", err)
	}
	if len(result.Apps) != 0 {
		t.Errorf("expected 0 apps, got %d", len(result.Apps))
	}
}

func TestParseHomarrEmpty(t *testing.T) {
	result, err := ParseHomarr(`{"apps": []}`)
	if err != nil {
		t.Fatalf("ParseHomarr empty returned error: %v", err)
	}
	if len(result.Apps) != 0 {
		t.Errorf("expected 0 apps, got %d", len(result.Apps))
	}
}
