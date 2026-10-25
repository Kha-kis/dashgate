package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"dashgate/internal/database"
	"dashgate/internal/discovery"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

type ignoreRuleInput struct {
	Source     string `json:"source"`
	Origin     string `json:"origin"`
	PathPrefix string `json:"pathPrefix"`
	Enabled    *bool  `json:"enabled"`
}

func decodeIgnoreRuleInput(w http.ResponseWriter, r *http.Request) (models.DiscoveryIgnoreRule, error) {
	var input ignoreRuleInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		return models.DiscoveryIgnoreRule{}, errors.New("extra JSON data")
	}
	if input.Enabled == nil {
		return models.DiscoveryIgnoreRule{}, errors.New("enabled is required")
	}
	rule, err := discovery.NormalizeIgnoreRule(input.Source, input.Origin, input.PathPrefix)
	if err != nil {
		return models.DiscoveryIgnoreRule{}, err
	}
	rule.Enabled = *input.Enabled
	return rule, nil
}

func respondIgnoreRuleWriteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, database.ErrDiscoveryIgnoreRuleDuplicate):
		respondError(w, http.StatusConflict, "An identical ignore rule already exists")
	case errors.Is(err, database.ErrDiscoveryIgnoreRuleLimit):
		respondError(w, http.StatusConflict, "Ignore rule limit reached (100)")
	case errors.Is(err, database.ErrDiscoveryIgnoreRuleNotFound):
		respondError(w, http.StatusNotFound, "Ignore rule not found")
	default:
		respondError(w, http.StatusInternalServerError, "Failed to save ignore rule")
	}
}

// DiscoveryIgnoreRulesHandler lists and creates source-scoped inbox rules.
func DiscoveryIgnoreRulesHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rules, err := database.ListDiscoveryIgnoreRules(app)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "Failed to load ignore rules")
				return
			}
			respondJSON(w, http.StatusOK, map[string]interface{}{"rules": rules})
		case http.MethodPost:
			rule, err := decodeIgnoreRuleInput(w, r)
			if err != nil {
				respondError(w, http.StatusBadRequest, "Invalid ignore rule")
				return
			}
			created, err := database.CreateDiscoveryIgnoreRule(app, rule)
			if err != nil {
				respondIgnoreRuleWriteError(w, err)
				return
			}
			respondJSON(w, http.StatusCreated, map[string]interface{}{"rule": created})
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

// DiscoveryIgnoreRuleByIDHandler updates or deletes a saved rule.
func DiscoveryIgnoreRuleByIDHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodDelete {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		idText := strings.TrimPrefix(r.URL.Path, "/api/admin/discovery-ignore-rules/")
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil || id <= 0 {
			respondError(w, http.StatusBadRequest, "Invalid ignore rule ID")
			return
		}
		if r.Method == http.MethodDelete {
			if err := database.DeleteDiscoveryIgnoreRule(app, id); err != nil {
				respondIgnoreRuleWriteError(w, err)
				return
			}
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		rule, err := decodeIgnoreRuleInput(w, r)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid ignore rule")
			return
		}
		rule.ID = id
		if err := database.UpdateDiscoveryIgnoreRule(app, rule); err != nil {
			respondIgnoreRuleWriteError(w, err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// DiscoveryIgnoreRulePreviewHandler lists current actionable matches for an unsaved rule.
func DiscoveryIgnoreRulePreviewHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		rule, err := decodeIgnoreRuleInput(w, r)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid ignore rule")
			return
		}
		ignored, err := database.ListIgnoredDiscoveredApps(app)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to preview ignore rule")
			return
		}
		ignoredKeys := make(map[string]bool, len(ignored))
		for _, item := range ignored {
			ignoredKeys[item.Source+"\x00"+item.URL] = true
		}
		rules, err := database.ListDiscoveryIgnoreRules(app)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to preview ignore rule")
			return
		}
		rawApps := discovery.GetAllRawDiscoveredApps(app)
		coveredKeys := make(map[string]bool)
		for _, match := range discovery.MatchIgnoreRules(rules, rawApps) {
			coveredKeys[match.Source+"\x00"+match.URL] = true
		}
		matches := make([]models.DiscoveredAppWithOverride, 0)
		count := 0
		seen := make(map[string]bool)
		for _, found := range rawApps {
			key := found.Source + "\x00" + found.URL
			if seen[key] || ignoredKeys[key] || coveredKeys[key] || !discovery.MatchesIgnoreRule(rule, found) {
				continue
			}
			seen[key] = true
			count++
			if len(matches) < 100 {
				matches = append(matches, found)
			}
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{"count": count, "matches": matches})
	}
}
