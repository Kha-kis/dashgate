package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"dashgate/internal/database"
	"dashgate/internal/server"

	"github.com/coreos/go-oidc/v3/oidc"
)

// isValidRedirect checks that a redirect URL is a safe relative path.
// It must start with "/", must not start with "//", and must not contain "://".
func isValidRedirect(url string) bool {
	if !strings.HasPrefix(url, "/") {
		return false
	}
	if strings.HasPrefix(url, "//") {
		return false
	}
	if strings.Contains(url, "://") {
		return false
	}
	// Block backslashes - some browsers treat \ as /, enabling open redirect via /\evil.com
	if strings.Contains(url, "\\") {
		return false
	}
	return true
}

// OIDCAuthHandler initiates the OIDC authorization code flow by generating a
// state parameter and redirecting the user to the OIDC provider.
func OIDCAuthHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.SysConfigMu.RLock()
		oidcEnabled := app.SystemConfig.OIDCAuthEnabled
		oauth2Config := app.OAuth2Config
		app.SysConfigMu.RUnlock()

		if !oidcEnabled || oauth2Config == nil {
			http.Error(w, "OIDC not configured", http.StatusServiceUnavailable)
			return
		}

		// Generate state
		stateBytes := make([]byte, 16)
		if _, err := rand.Read(stateBytes); err != nil {
			log.Printf("Failed to generate OIDC state: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		state := base64.URLEncoding.EncodeToString(stateBytes)

		// Store state with redirect URL
		redirectURL := r.URL.Query().Get("redirect")
		if !isValidRedirect(redirectURL) {
			redirectURL = "/"
		}

		if app.DB != nil {
			if err := database.CreateOIDCState(app, state, redirectURL); err != nil {
				log.Printf("Failed to store OIDC state: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			// Clean up old states (best-effort)
			database.CleanOldOIDCStates(app)
		}

		// Redirect to OIDC provider
		authURL := oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// OIDCCallbackHandler handles the OIDC provider callback, exchanging the
// authorization code for tokens, verifying the ID token, extracting user
// claims, and creating a local session.
func OIDCCallbackHandler(app *server.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.SysConfigMu.RLock()
		oidcEnabled := app.SystemConfig.OIDCAuthEnabled
		oauth2Config := app.OAuth2Config
		oidcProvider := app.OIDCProvider
		app.SysConfigMu.RUnlock()

		if !oidcEnabled || oauth2Config == nil || oidcProvider == nil {
			http.Error(w, "OIDC not configured", http.StatusServiceUnavailable)
			return
		}

		// Verify state
		state := r.URL.Query().Get("state")
		var redirectURL string
		if app.DB == nil {
			http.Error(w, "OIDC authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		redirectURL, err := database.GetOIDCState(app, state)
		if err != nil {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}
		database.DeleteOIDCState(app, state)
		if !isValidRedirect(redirectURL) {
			redirectURL = "/"
		}

		// Check for error from provider
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			errDesc := r.URL.Query().Get("error_description")
			log.Printf("OIDC error: %s - %s", errMsg, errDesc)
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		// Exchange code for token
		code := r.URL.Query().Get("code")
		ctx := context.Background()
		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			log.Printf("OIDC token exchange failed: %v", err)
			http.Error(w, "Token exchange failed", http.StatusInternalServerError)
			return
		}

		// Verify ID token
		verifier := oidcProvider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No ID token in response", http.StatusInternalServerError)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Printf("OIDC token verification failed: %v", err)
			http.Error(w, "Token verification failed", http.StatusUnauthorized)
			return
		}

		// Extract claims
		var claims struct {
			Subject           string   `json:"sub"`
			Email             string   `json:"email"`
			Name              string   `json:"name"`
			PreferredUsername string   `json:"preferred_username"`
			Groups            []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			log.Printf("Failed to parse OIDC claims: %v", err)
			http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
			return
		}

		// Also try to get groups from custom claim
		var rawClaims map[string]interface{}
		if err := idToken.Claims(&rawClaims); err != nil {
			log.Printf("Failed to parse raw OIDC claims: %v", err)
		}
		app.SysConfigMu.RLock()
		groupsClaimName := app.SystemConfig.OIDCGroupsClaim
		app.SysConfigMu.RUnlock()
		if groupsClaim, ok := rawClaims[groupsClaimName]; ok {
			switch g := groupsClaim.(type) {
			case []interface{}:
				for _, v := range g {
					if s, ok := v.(string); ok {
						claims.Groups = append(claims.Groups, s)
					}
				}
			case []string:
				claims.Groups = g
			}
		}

		// Determine username
		username := claims.PreferredUsername
		if username == "" {
			username = claims.Email
		}
		if username == "" {
			username = claims.Subject
		}

		displayName := claims.Name
		if displayName == "" {
			displayName = username
		}

		// Create or update user in database using upsert to avoid race conditions
		var userID int
		groupsJSON, _ := json.Marshal(claims.Groups)
		if err := database.UpsertOIDCUser(app, username, claims.Email, displayName, string(groupsJSON)); err != nil {
			log.Printf("Failed to upsert OIDC user: %v", err)
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
		userID, err = database.GetUserIDByUsername(app, username)
		if err != nil {
			log.Printf("Failed to retrieve OIDC user ID: %v", err)
			http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
			return
		}

		// Invalidate any existing sessions for this user to prevent session fixation
		database.InvalidateUserSessions(app, userID)

		// Create session
		sessionToken, err := GenerateSessionToken()
		if err != nil {
			log.Printf("Error generating session token: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		expiresAt := time.Now().Add(time.Duration(app.AuthConfig.SessionDuration) * 24 * time.Hour)
		if err := database.CreateSession(app, userID, sessionToken, expiresAt); err != nil {
			log.Printf("Error creating session: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set cookie
		http.SetCookie(w, &http.Cookie{
			Name:     app.AuthConfig.CookieName,
			Value:    sessionToken,
			Path:     "/",
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   app.AuthConfig.CookieSecure,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}
