package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"dashgate/internal/auth"
	"dashgate/internal/config"
	"dashgate/internal/discovery"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

// accessDecision describes the same visibility decision made by the dashboard.
type accessDecision struct {
	Visible      bool   `json:"visible"`
	Reason       string `json:"reason"`
	MatchedGroup string `json:"matchedGroup,omitempty"`
}

func matchingGroup(required, user []string) (string, bool) {
	groupSet := make(map[string]bool, len(user))
	for _, group := range user {
		groupSet[strings.TrimSpace(group)] = true
	}
	for _, group := range required {
		if groupSet[group] {
			return group, true
		}
	}
	return "", false
}

func explainConfigAccess(required, user []string, isAdmin bool) accessDecision {
	if isAdmin {
		return accessDecision{Visible: true, Reason: "admin"}
	}
	if len(required) == 0 {
		return accessDecision{Reason: "admin_only"}
	}
	if group, ok := matchingGroup(required, user); ok {
		return accessDecision{Visible: true, Reason: "group_match", MatchedGroup: group}
	}
	return accessDecision{Reason: "no_group_match"}
}

func explainDiscoveredAccess(override *models.DiscoveredAppOverride, user []string, isAdmin bool) accessDecision {
	if override == nil {
		return accessDecision{Reason: "unpublished"}
	}
	if override.Hidden {
		return accessDecision{Reason: "hidden"}
	}
	if isAdmin {
		return accessDecision{Visible: true, Reason: "admin"}
	}
	if len(override.Groups) == 0 {
		return accessDecision{Visible: true, Reason: "everyone"}
	}
	if group, ok := matchingGroup(override.Groups, user); ok {
		return accessDecision{Visible: true, Reason: "group_match", MatchedGroup: group}
	}
	return accessDecision{Reason: "no_group_match"}
}

type accessApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// AccessAppsHandler lists every current app source, including entries with
// duplicate URLs that the regular app-management list intentionally omits.
func AccessAppsHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		apps := make([]accessApp, 0)
		app.ConfigMu.RLock()
		for categoryIndex, category := range app.Config.Categories {
			for appIndex, configured := range category.Apps {
				apps = append(apps, accessApp{ID: fmt.Sprintf("config:%d:%d", categoryIndex, appIndex), Name: configured.Name, URL: configured.URL, Source: "config"})
			}
		}
		app.ConfigMu.RUnlock()
		for index, discovered := range discovery.GetAllRawDiscoveredApps(app) {
			name := discovered.Name
			if discovered.Override != nil && discovered.Override.NameOverride != "" {
				name = discovered.Override.NameOverride
			}
			apps = append(apps, accessApp{ID: fmt.Sprintf("discovered:%d", index), Name: name, URL: discovered.URL, Source: discovered.Source})
		}
		respondJSON(w, http.StatusOK, apps)
	}
}

type accessUser struct {
	ID        int      `json:"id"`
	Username  string   `json:"username"`
	Source    string   `json:"source"`
	Groups    []string `json:"groups"`
	UpdatedAt string   `json:"updatedAt"`
}

func userSource(passwordHash string) string {
	switch passwordHash {
	case "OIDC_USER":
		return "oidc"
	case "LDAP_USER":
		return "ldap"
	case "PROXY_USER":
		return "proxy"
	default:
		return "local"
	}
}

func scanAccessUser(row interface{ Scan(...any) error }) (*accessUser, error) {
	var user accessUser
	var passwordHash, groupsJSON string
	err := row.Scan(&user.ID, &user.Username, &passwordHash, &groupsJSON, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	user.Source = userSource(passwordHash)
	if err := json.Unmarshal([]byte(groupsJSON), &user.Groups); err != nil {
		return nil, err
	}
	if user.Groups == nil {
		user.Groups = []string{}
	}
	return &user, nil
}

func readAccessUser(app *server.App, id int) (*accessUser, error) {
	return scanAccessUser(app.DB.QueryRow(`SELECT id, username, password_hash, COALESCE(groups,'[]'),
		COALESCE(updated_at,'') FROM users WHERE id = ?`, id))
}

// AccessUsersHandler lists saved identities for the admin's read-only checker.
func AccessUsersHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		if app.DB == nil {
			respondError(w, http.StatusServiceUnavailable, "User database unavailable")
			return
		}
		rows, err := app.DB.Query(`SELECT id, username, password_hash, COALESCE(groups,'[]'),
			COALESCE(updated_at,'') FROM users ORDER BY username`)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to list users")
			return
		}
		defer rows.Close()
		users := make([]accessUser, 0)
		for rows.Next() {
			user, err := scanAccessUser(rows)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "Failed to read user")
				return
			}
			users = append(users, *user)
		}
		if err := rows.Err(); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to list users")
			return
		}
		respondJSON(w, http.StatusOK, users)
	}
}

type accessCheckResult struct {
	accessDecision
	AppName   string     `json:"appName"`
	AppSource string     `json:"appSource"`
	AppGroups []string   `json:"appGroups"`
	User      accessUser `json:"user"`
}

// AccessCheckHandler explains dashboard visibility from saved user and app state.
func AccessCheckHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		id, err := strconv.Atoi(r.URL.Query().Get("userId"))
		source, appURL := r.URL.Query().Get("source"), r.URL.Query().Get("appUrl")
		appID, appName := r.URL.Query().Get("appId"), r.URL.Query().Get("appName")
		if err != nil || id <= 0 || source == "" || appURL == "" || appID == "" {
			respondError(w, http.StatusBadRequest, "User and app are required")
			return
		}
		if app.DB == nil {
			respondError(w, http.StatusServiceUnavailable, "User database unavailable")
			return
		}
		user, err := readAccessUser(app, id)
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "User not found")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to read user")
			return
		}
		isAdmin := auth.CheckIsAdmin(app, user.Groups)
		result := accessCheckResult{User: *user, AppGroups: []string{}}
		if source == "config" {
			var categoryIndex, appIndex int
			if _, err := fmt.Sscanf(appID, "config:%d:%d", &categoryIndex, &appIndex); err != nil || categoryIndex < 0 || appIndex < 0 {
				respondError(w, http.StatusBadRequest, "Invalid app selection")
				return
			}
			app.ConfigMu.RLock()
			var found *models.App
			if categoryIndex < len(app.Config.Categories) && appIndex < len(app.Config.Categories[categoryIndex].Apps) {
				candidate := app.Config.Categories[categoryIndex].Apps[appIndex]
				if candidate.URL == appURL && candidate.Name == appName {
					found = &candidate
				}
			}
			app.ConfigMu.RUnlock()
			if found == nil {
				respondError(w, http.StatusNotFound, "App not found")
				return
			}
			result.AppName, result.AppSource = found.Name, "config"
			result.AppGroups = append([]string{}, config.GetAppGroups(app, *found)...)
			result.accessDecision = explainConfigAccess(result.AppGroups, user.Groups, isAdmin)
		} else {
			var discoveredIndex int
			if _, err := fmt.Sscanf(appID, "discovered:%d", &discoveredIndex); err != nil || discoveredIndex < 0 {
				respondError(w, http.StatusBadRequest, "Invalid app selection")
				return
			}
			var found *models.DiscoveredAppWithOverride
			raw := discovery.GetAllRawDiscoveredApps(app)
			if discoveredIndex < len(raw) {
				candidate := raw[discoveredIndex]
				name := candidate.Name
				if candidate.Override != nil && candidate.Override.NameOverride != "" {
					name = candidate.Override.NameOverride
				}
				if candidate.Source == source && candidate.URL == appURL && name == appName {
					found = &candidate
				}
			}
			if found == nil {
				respondError(w, http.StatusNotFound, "App not found")
				return
			}
			result.AppName, result.AppSource = found.Name, found.Source
			if found.Override != nil {
				result.AppGroups = append([]string{}, found.Override.Groups...)
				if found.Override.NameOverride != "" {
					result.AppName = found.Override.NameOverride
				}
			}
			result.accessDecision = explainDiscoveredAccess(found.Override, user.Groups, isAdmin)
			if result.Visible {
				app.ConfigMu.RLock()
				for _, cat := range app.Config.Categories {
					for _, candidate := range cat.Apps {
						if candidate.URL == found.URL && explainConfigAccess(config.GetAppGroups(app, candidate), user.Groups, isAdmin).Visible {
							result.accessDecision = accessDecision{Reason: "shown_as_config"}
						}
					}
				}
				app.ConfigMu.RUnlock()
			}
		}
		respondJSON(w, http.StatusOK, result)
	}
}
