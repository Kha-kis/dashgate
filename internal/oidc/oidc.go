package oidc

import (
	"context"
	"log"
	"strings"
	"time"

	"dashgate/internal/server"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func InitOIDCProvider(app *server.App, issuer, clientID, clientSecret, redirectURL, scopes, groupsClaim string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Printf("Failed to initialize OIDC provider: %v", err)
		return
	}

	scopeList := []string{oidc.ScopeOpenID, "profile", "email"}
	if scopes != "" {
		scopeList = strings.Split(scopes, " ")
	}

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopeList,
	}

	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	app.SysConfigMu.Lock()
	app.OIDCProvider = provider
	app.OAuth2Config = oauthConfig
	app.SystemConfig.OIDCGroupsClaim = groupsClaim
	app.SysConfigMu.Unlock()

	log.Printf("OIDC auth configured: %s", issuer)
}
