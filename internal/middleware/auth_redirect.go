package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"dashgate/internal/auth"
	"dashgate/internal/models"
	"dashgate/internal/server"
)

func AutoLoginRedirect(app *server.App, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !app.SystemConfig.SetupCompleted {
			next.ServeHTTP(w, r)
			return
		}

		publicPaths := []string{
			"/login",
			"/logout",
			"/setup",
			"/health",
			"/api/health",
			"/api/auth/",
			"/static/",
			"/manifest.json",
			"/sw.js",
			"/offline",
			"/auth/oidc",
		}

		for _, path := range publicPaths {
			if strings.HasPrefix(r.URL.Path, path) {
				next.ServeHTTP(w, r)
				return
			}
		}

		user := auth.GetAuthenticatedUser(app, r)
		if user == nil {
			isAPIRequest := strings.Contains(r.Header.Get("Accept"), "application/json") ||
				strings.HasPrefix(r.URL.Path, "/api/")

			if isAPIRequest {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error":    "unauthorized",
					"redirect": GetAuthRedirectURL(app),
				})
				return
			}

			http.Redirect(w, r, GetAuthRedirectURL(app), http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func GetAuthRedirectURL(app *server.App) string {
	switch app.AuthConfig.Mode {
	case models.AuthModeAuthelia:
		return "/auth/oidc"
	case models.AuthModeLocal, models.AuthModeHybrid:
		return "/login"
	default:
		return "/login"
	}
}
