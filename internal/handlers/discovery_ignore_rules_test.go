package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dashgate/internal/auth"
	"dashgate/internal/database"
	"dashgate/internal/middleware"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

func ruleRequest(app *server.App, method, path string, body interface{}) *httptest.ResponseRecorder {
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	w := httptest.NewRecorder()
	switch {
	case strings.HasSuffix(path, "/preview"):
		DiscoveryIgnoreRulePreviewHandler(app)(w, req)
	case strings.HasPrefix(path, "/api/admin/discovery-ignore-rules/"):
		DiscoveryIgnoreRuleByIDHandler(app)(w, req)
	default:
		DiscoveryIgnoreRulesHandler(app)(w, req)
	}
	return w
}

func ruleBody(source, origin, path string, enabled bool) map[string]interface{} {
	return map[string]interface{}{"source": source, "origin": origin, "pathPrefix": path, "enabled": enabled}
}

func createdRuleID(t *testing.T, w *httptest.ResponseRecorder) int64 {
	t.Helper()
	if w.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Rule models.DiscoveryIgnoreRule `json:"rule"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Rule.ID == 0 {
		t.Fatalf("created rule: %+v, %v", body, err)
	}
	return body.Rule.ID
}

func ruleMatchesFromAdmin(t *testing.T, app *server.App) []models.DiscoveryRuleMatch {
	t.Helper()
	w := httptest.NewRecorder()
	AdminDiscoveredAppsHandler(app)(w, newGet("/api/admin/discovered-apps"))
	if w.Code != http.StatusOK {
		t.Fatalf("admin discovered status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Active      []models.DiscoveredAppWithOverride `json:"active"`
		Ignored     []models.IgnoredDiscoveredApp      `json:"ignored"`
		IgnoreRules []models.DiscoveryIgnoreRule       `json:"ignoreRules"`
		RuleMatches []models.DiscoveryRuleMatch        `json:"ruleMatches"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.IgnoreRules == nil || body.RuleMatches == nil || body.Active == nil || body.Ignored == nil {
		t.Fatalf("admin response: %+v, %v", body, err)
	}
	return body.RuleMatches
}

func TestDiscoveryIgnoreRulePreviewCRUDAndManualRestore(t *testing.T) {
	app := ignoredTestApp(t)
	app.NginxDiscovery.Enabled = true
	app.NginxDiscovery.SetApps([]models.App{
		{Name: "Health", URL: "https://example.test/health"},
		{Name: "Health live", URL: "https://example.test/health/live"},
		{Name: "Published", URL: "https://example.test/health/published"},
	})
	app.DiscoveredOverrides["https://example.test/health/published"] = &models.DiscoveredAppOverride{URL: "https://example.test/health/published", Hidden: false}
	input := ruleBody("nginx", "https://example.test", "/health", true)
	preview := ruleRequest(app, http.MethodPost, "/api/admin/discovery-ignore-rules/preview", input)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview %d: %s", preview.Code, preview.Body.String())
	}
	var before struct {
		Count   int                                `json:"count"`
		Matches []models.DiscoveredAppWithOverride `json:"matches"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &before); err != nil || before.Count != 2 || len(before.Matches) != 2 {
		t.Fatalf("preview body: %+v, %v", before, err)
	}
	id := createdRuleID(t, ruleRequest(app, http.MethodPost, "/api/admin/discovery-ignore-rules", input))
	matches := ruleMatchesFromAdmin(t, app)
	if len(matches) != 2 || matches[0].RuleID != id || matches[1].RuleID != id {
		t.Fatalf("saved matches: %+v", matches)
	}
	if got := ignoredAction(t, app, "dismiss", map[string]string{"source": "nginx", "url": "https://example.test/health"}); got != http.StatusOK {
		t.Fatalf("manual dismiss status %d", got)
	}
	if got := ignoredAction(t, app, "restore", map[string]string{"source": "nginx", "url": "https://example.test/health"}); got != http.StatusOK {
		t.Fatalf("manual restore status %d", got)
	}
	if matches := ruleMatchesFromAdmin(t, app); len(matches) != 2 {
		t.Fatalf("restore incorrectly changed rule matches: %+v", matches)
	}
	update := ruleBody("nginx", "https://example.test", "/health", false)
	if w := ruleRequest(app, http.MethodPut, fmt.Sprintf("/api/admin/discovery-ignore-rules/%d", id), update); w.Code != http.StatusOK {
		t.Fatalf("disable %d: %s", w.Code, w.Body.String())
	}
	if matches := ruleMatchesFromAdmin(t, app); len(matches) != 0 {
		t.Fatalf("disabled matches: %+v", matches)
	}
	if w := ruleRequest(app, http.MethodDelete, fmt.Sprintf("/api/admin/discovery-ignore-rules/%d", id), nil); w.Code != http.StatusOK {
		t.Fatalf("delete %d: %s", w.Code, w.Body.String())
	}
	if w := ruleRequest(app, http.MethodGet, "/api/admin/discovery-ignore-rules", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "\"rules\":[]") {
		t.Fatalf("list after delete %d: %s", w.Code, w.Body.String())
	}
}

func TestDiscoveryIgnoreRuleOverlapsAndEmptyPreview(t *testing.T) {
	app := ignoredTestApp(t)
	app.NginxDiscovery.Enabled = true
	app.NginxDiscovery.SetApps([]models.App{{Name: "Live", URL: "https://example.test/health/live"}})
	first := createdRuleID(t, ruleRequest(app, http.MethodPost, "/api/admin/discovery-ignore-rules", ruleBody("nginx", "https://example.test", "/health", true)))
	createdRuleID(t, ruleRequest(app, http.MethodPost, "/api/admin/discovery-ignore-rules", ruleBody("nginx", "https://example.test", "/health/live", true)))
	matches := ruleMatchesFromAdmin(t, app)
	if len(matches) != 1 || matches[0].RuleID != first {
		t.Fatalf("overlap matches: %+v", matches)
	}
	empty := ruleBody("docker", "https://future.test", "/hooks", true)
	preview := ruleRequest(app, http.MethodPost, "/api/admin/discovery-ignore-rules/preview", empty)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), "\"count\":0") {
		t.Fatalf("empty preview %d: %s", preview.Code, preview.Body.String())
	}
	createdRuleID(t, ruleRequest(app, http.MethodPost, "/api/admin/discovery-ignore-rules", empty))
}

func TestDiscoveryIgnoreRuleRejectsInvalidAndFailedRequests(t *testing.T) {
	app := ignoredTestApp(t)
	endpoint := "/api/admin/discovery-ignore-rules"
	for _, body := range []interface{}{
		ruleBody("all", "https://example.test", "/health", true),
		ruleBody("nginx", "https://example.test", "/", true),
		map[string]interface{}{"source": "nginx", "origin": "https://example.test", "pathPrefix": "/health", "enabled": true, "unexpected": 1},
	} {
		if w := ruleRequest(app, http.MethodPost, endpoint, body); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid body status %d: %s", w.Code, w.Body.String())
		}
	}
	large := strings.Repeat("x", 17000)
	if w := ruleRequest(app, http.MethodPost, endpoint, map[string]string{"origin": large}); w.Code != http.StatusBadRequest {
		t.Fatalf("oversize status %d", w.Code)
	}
	if w := ruleRequest(app, http.MethodPatch, endpoint, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method %d", w.Code)
	}
	if w := ruleRequest(app, http.MethodDelete, endpoint+"/bogus", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad ID status %d", w.Code)
	}
	if w := ruleRequest(app, http.MethodDelete, endpoint+"/999", nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing ID status %d", w.Code)
	}
	input := ruleBody("nginx", "https://example.test", "/health", true)
	createdRuleID(t, ruleRequest(app, http.MethodPost, endpoint, input))
	if w := ruleRequest(app, http.MethodPost, endpoint, input); w.Code != http.StatusConflict {
		t.Fatalf("duplicate status %d: %s", w.Code, w.Body.String())
	}
	for i := 1; i < 100; i++ {
		_, err := database.CreateDiscoveryIgnoreRule(app, models.DiscoveryIgnoreRule{Source: "nginx", Origin: "https://example.test", PathPrefix: fmt.Sprintf("/path%d", i), Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	if w := ruleRequest(app, http.MethodPost, endpoint, ruleBody("nginx", "https://example.test", "/over", true)); w.Code != http.StatusConflict {
		t.Fatalf("limit status %d", w.Code)
	}
	app.DB.Close()
	if w := ruleRequest(app, http.MethodGet, endpoint, nil); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "sql:") {
		t.Fatalf("database failure response %d: %s", w.Code, w.Body.String())
	}
}

func TestDiscoveryIgnoreRuleAdminAndCSRFMiddleware(t *testing.T) {
	app := ignoredTestApp(t)
	handler := auth.RequireAdmin(app, DiscoveryIgnoreRulesHandler(app))
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/api/admin/discovery-ignore-rules", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status %d", w.Code)
	}
	readerID := seedUser(t, app, "reader", "letmein", "Reader", false)
	seedSession(t, app, readerID, "rule-reader-session")
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/discovery-ignore-rules", nil)
	req.AddCookie(&http.Cookie{Name: "test_session", Value: "rule-reader-session"})
	handler(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin status %d", w.Code)
	}
	w = httptest.NewRecorder()
	middleware.CSRFProtection(http.HandlerFunc(DiscoveryIgnoreRulesHandler(app))).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/admin/discovery-ignore-rules", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status %d", w.Code)
	}
}
