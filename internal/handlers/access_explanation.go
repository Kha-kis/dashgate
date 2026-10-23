package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

// A catalog ID binds its position to the current entry without putting app
// URLs (which may contain credentials) in access-check request URLs.
func catalogID(app *server.App, position string, entry any) string {
	data, _ := json.Marshal(entry)
	mac := hmac.New(sha256.New, app.EncryptionKey)
	mac.Write([]byte(position))
	mac.Write([]byte{0})
	mac.Write(data)
	return position + ":" + hex.EncodeToString(mac.Sum(nil))
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
				position := fmt.Sprintf("config:%d:%d", categoryIndex, appIndex)
				apps = append(apps, accessApp{ID: catalogID(app, position, struct {
					Category string
					App      models.App
					Groups   []string
				}{category.Name, configured, config.GetAppGroups(app, configured)}), Name: configured.Name, URL: configured.URL, Source: "config"})
			}
		}
		app.ConfigMu.RUnlock()
		for index, discovered := range discovery.GetAllRawDiscoveredApps(app) {
			name := discovered.Name
			if discovered.Override != nil && discovered.Override.NameOverride != "" {
				name = discovered.Override.NameOverride
			}
			position := fmt.Sprintf("discovered:%d", index)
			apps = append(apps, accessApp{ID: catalogID(app, position, discovered), Name: name, URL: discovered.URL, Source: discovered.Source})
		}
		respondJSON(w, http.StatusOK, apps)
	}
}

type accessUser struct {
	ID            int      `json:"id"`
	Username      string   `json:"username"`
	Source        string   `json:"source"`
	Groups        []string `json:"groups"`
	GroupsInvalid bool     `json:"groupsInvalid,omitempty"`
	UpdatedAt     string   `json:"updatedAt"`
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
		user.GroupsInvalid = true
		user.Groups = []string{}
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
		appID := r.URL.Query().Get("appId")
		parts := strings.Split(appID, ":")
		if err != nil || id <= 0 || len(parts) < 3 {
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
		if parts[0] == "config" {
			if len(parts) != 4 {
				respondError(w, http.StatusBadRequest, "Invalid app selection")
				return
			}
			categoryIndex, categoryErr := strconv.Atoi(parts[1])
			appIndex, appErr := strconv.Atoi(parts[2])
			if categoryErr != nil || appErr != nil || categoryIndex < 0 || appIndex < 0 {
				respondError(w, http.StatusBadRequest, "Invalid app selection")
				return
			}
			app.ConfigMu.RLock()
			var found *models.App
			if categoryIndex < len(app.Config.Categories) && appIndex < len(app.Config.Categories[categoryIndex].Apps) {
				candidate := app.Config.Categories[categoryIndex].Apps[appIndex]
				position := fmt.Sprintf("config:%d:%d", categoryIndex, appIndex)
				if hmac.Equal([]byte(catalogID(app, position, struct {
					Category string
					App      models.App
					Groups   []string
				}{app.Config.Categories[categoryIndex].Name, candidate, config.GetAppGroups(app, candidate)})), []byte(appID)) {
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
		} else if parts[0] == "discovered" {
			if len(parts) != 3 {
				respondError(w, http.StatusBadRequest, "Invalid app selection")
				return
			}
			discoveredIndex, indexErr := strconv.Atoi(parts[1])
			if indexErr != nil || discoveredIndex < 0 {
				respondError(w, http.StatusBadRequest, "Invalid app selection")
				return
			}
			var found *models.DiscoveredAppWithOverride
			raw := discovery.GetAllRawDiscoveredApps(app)
			if discoveredIndex < len(raw) {
				candidate := raw[discoveredIndex]
				if hmac.Equal([]byte(catalogID(app, fmt.Sprintf("discovered:%d", discoveredIndex), candidate)), []byte(appID)) {
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
		} else {
			respondError(w, http.StatusBadRequest, "Invalid app selection")
			return
		}
		respondJSON(w, http.StatusOK, result)
	}
}
