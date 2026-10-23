package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"dashgate/internal/models"
	"dashgate/internal/server"
)

func TestExplainConfigAccess(t *testing.T) {
	tests := []struct {
		name            string
		required, user  []string
		admin, visible  bool
		reason, matched string
	}{
		{"admin bypass", nil, nil, true, true, "admin", ""},
		{"empty groups are admin only", nil, []string{"users"}, false, false, "admin_only", ""},
		{"matching group", []string{"media"}, []string{"media"}, false, true, "group_match", "media"},
		{"exact group names", []string{"Media"}, []string{"media"}, false, false, "no_group_match", ""},
		{"empty name still matches", []string{""}, []string{""}, false, true, "group_match", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := explainConfigAccess(tt.required, tt.user, tt.admin)
			if got.Visible != tt.visible || got.Reason != tt.reason || got.MatchedGroup != tt.matched {
				t.Fatalf("got %+v, want visible=%v reason=%s matched=%s", got, tt.visible, tt.reason, tt.matched)
			}
		})
	}
}

func TestExplainDiscoveredAccess(t *testing.T) {
	tests := []struct {
		name           string
		override       *models.DiscoveredAppOverride
		groups         []string
		admin, visible bool
		reason         string
	}{
		{"unpublished", nil, nil, true, false, "unpublished"},
		{"hidden", &models.DiscoveredAppOverride{Hidden: true}, nil, true, false, "hidden"},
		{"empty groups public", &models.DiscoveredAppOverride{}, nil, false, true, "everyone"},
		{"admin bypass", &models.DiscoveredAppOverride{Groups: []string{"media"}}, nil, true, true, "admin"},
		{"group blocked", &models.DiscoveredAppOverride{Groups: []string{"media"}}, []string{"users"}, false, false, "no_group_match"},
		{"empty name still matches", &models.DiscoveredAppOverride{Groups: []string{""}}, []string{""}, false, true, "group_match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := explainDiscoveredAccess(tt.override, tt.groups, tt.admin)
			if got.Visible != tt.visible || got.Reason != tt.reason {
				t.Fatalf("got %+v, want visible=%v reason=%s", got, tt.visible, tt.reason)
			}
		})
	}
}

func TestAccessUsersHandlerOmitsCredentials(t *testing.T) {
	app := setupTestAppWithDB(t)
	seedUser(t, app, "alice", "secret-password", "Alice", false)
	w := httptest.NewRecorder()
	AccessUsersHandler(app)(w, httptest.NewRequest(http.MethodGet, "/api/admin/access-users", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var users []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0]["source"] != "local" {
		t.Fatalf("users = %+v", users)
	}
	if _, ok := users[0]["passwordHash"]; ok {
		t.Fatal("credential exposed")
	}
	if strings.Contains(w.Body.String(), "secret-password") {
		t.Fatal("credential exposed in response body")
	}
}

func TestAccessCheckHandlerUsesEffectiveMappingAndStoredOIDCGroups(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "oidc-user", "unused-password", "OIDC User", false)
	if _, err := app.DB.Exec("UPDATE users SET password_hash = 'OIDC_USER', groups = '[\"media\"]' WHERE id = ?", userID); err != nil {
		t.Fatal(err)
	}
	app.Config.Categories = []models.Category{{Name: "Tools", Apps: []models.App{{Name: "Media", URL: "https://media.test", Groups: []string{"other"}}}}}
	app.AppMappings = map[string][]string{"https://media.test": {"media"}}
	w := httptest.NewRecorder()
	url := "/api/admin/access-check?userId=" + strconv.Itoa(userID) + "&source=config&appUrl=https%3A%2F%2Fmedia.test&appId=config%3A0%3A0&appName=Media"
	AccessCheckHandler(app)(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var result struct {
		Visible      bool     `json:"visible"`
		Reason       string   `json:"reason"`
		MatchedGroup string   `json:"matchedGroup"`
		AppGroups    []string `json:"appGroups"`
		User         struct {
			Source string `json:"source"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Visible || result.Reason != "group_match" || result.MatchedGroup != "media" || result.User.Source != "oidc" || len(result.AppGroups) != 1 || result.AppGroups[0] != "media" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAccessCheckHandlerEmptyConfigGroupsAreJSONList(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "reader", "unused-password", "Reader", false)
	app.Config.Categories = []models.Category{{Name: "Tools", Apps: []models.App{{Name: "Private", URL: "https://private.test"}}}}
	w := httptest.NewRecorder()
	url := "/api/admin/access-check?userId=" + strconv.Itoa(userID) + "&source=config&appUrl=https%3A%2F%2Fprivate.test&appId=config%3A0%3A0&appName=Private"
	AccessCheckHandler(app)(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if string(result["appGroups"]) != "[]" {
		t.Fatalf("appGroups = %s, want []", result["appGroups"])
	}
}

func TestAccessCheckHandlerRejectsInvalidSelection(t *testing.T) {
	app := setupTestAppWithDB(t)
	w := httptest.NewRecorder()
	AccessCheckHandler(app)(w, httptest.NewRequest(http.MethodGet, "/api/admin/access-check?userId=nope&source=config&appUrl=https://example.test", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAccessAppsHandlerIncludesDuplicateSourceAndOverrideName(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.Config.Categories = []models.Category{{Name: "Tools", Apps: []models.App{{Name: "Configured", URL: "https://same.test"}}}}
	app.DockerDiscovery = server.NewDiscoveryManager()
	app.TraefikDiscovery = server.NewDiscoveryManager()
	app.NginxDiscovery = server.NewDiscoveryManager()
	app.NPMDiscovery = server.NewDiscoveryManager()
	app.CaddyDiscovery = server.NewDiscoveryManager()
	app.UnraidDiscovery = server.NewDiscoveryManager()
	app.DockerDiscovery.Enabled = true
	app.DockerDiscovery.SetApps([]models.App{{Name: "Raw", URL: "https://same.test"}})
	app.DiscoveredOverrides = map[string]*models.DiscoveredAppOverride{"https://same.test": {NameOverride: "Renamed"}}
	w := httptest.NewRecorder()
	AccessAppsHandler(app)(w, httptest.NewRequest(http.MethodGet, "/api/admin/access-apps", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var apps []struct{ Name, Source, URL string }
	if err := json.Unmarshal(w.Body.Bytes(), &apps); err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 || apps[0].Source != "config" || apps[1].Source != "docker" || apps[1].Name != "Renamed" {
		t.Fatalf("apps = %+v", apps)
	}
}

func TestAccessAppsHandlerEmptyCatalogIsJSONList(t *testing.T) {
	app := setupTestAppWithDB(t)
	app.DockerDiscovery = server.NewDiscoveryManager()
	app.TraefikDiscovery = server.NewDiscoveryManager()
	app.NginxDiscovery = server.NewDiscoveryManager()
	app.NPMDiscovery = server.NewDiscoveryManager()
	app.CaddyDiscovery = server.NewDiscoveryManager()
	app.UnraidDiscovery = server.NewDiscoveryManager()
	w := httptest.NewRecorder()
	AccessAppsHandler(app)(w, httptest.NewRequest(http.MethodGet, "/api/admin/access-apps", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("body = %s", w.Body.String())
	}
}

func TestAccessCheckHandlerDiscoveredDuplicateCanBeVisible(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "reader", "unused-password", "Reader", false)
	app.Config.Categories = []models.Category{{Name: "Tools", Apps: []models.App{{Name: "Configured", URL: "https://same.test"}}}}
	app.DockerDiscovery = server.NewDiscoveryManager()
	app.TraefikDiscovery = server.NewDiscoveryManager()
	app.NginxDiscovery = server.NewDiscoveryManager()
	app.NPMDiscovery = server.NewDiscoveryManager()
	app.CaddyDiscovery = server.NewDiscoveryManager()
	app.UnraidDiscovery = server.NewDiscoveryManager()
	app.DockerDiscovery.Enabled = true
	app.DockerDiscovery.SetApps([]models.App{{Name: "Raw", URL: "https://same.test"}})
	app.DiscoveredOverrides = map[string]*models.DiscoveredAppOverride{"https://same.test": {NameOverride: "Renamed"}}
	w := httptest.NewRecorder()
	url := "/api/admin/access-check?userId=" + strconv.Itoa(userID) + "&source=docker&appUrl=https%3A%2F%2Fsame.test&appId=discovered%3A0&appName=Renamed"
	AccessCheckHandler(app)(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var result struct {
		Visible bool   `json:"visible"`
		Reason  string `json:"reason"`
		AppName string `json:"appName"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Visible || result.Reason != "everyone" || result.AppName != "Renamed" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAccessCheckHandlerSelectsSecondConfiguredDuplicate(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "reader", "unused-password", "Reader", false)
	app.Config.Categories = []models.Category{{Name: "Tools", Apps: []models.App{
		{Name: "First", URL: "https://same.test", Groups: []string{"media"}},
		{Name: "Second", URL: "https://same.test"},
	}}}
	w := httptest.NewRecorder()
	url := "/api/admin/access-check?userId=" + strconv.Itoa(userID) + "&source=config&appUrl=https%3A%2F%2Fsame.test&appId=config%3A0%3A1&appName=Second"
	AccessCheckHandler(app)(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var result struct{ Reason, AppName string }
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.AppName != "Second" || result.Reason != "admin_only" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAccessCheckHandlerAllowsUnnamedConfiguredApp(t *testing.T) {
	app := setupTestAppWithDB(t)
	userID := seedUser(t, app, "reader", "unused-password", "Reader", false)
	app.Config.Categories = []models.Category{{Name: "Tools", Apps: []models.App{{URL: "https://unnamed.test"}}}}
	w := httptest.NewRecorder()
	url := "/api/admin/access-check?userId=" + strconv.Itoa(userID) + "&source=config&appUrl=https%3A%2F%2Funnamed.test&appId=config%3A0%3A0&appName="
	AccessCheckHandler(app)(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusOK { t.Fatalf("status = %d: %s", w.Code, w.Body.String()) }
}
