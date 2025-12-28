package main

import (
	"context"
	"encoding/gob"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"go-oidc-example/internal/auth"
	"go-oidc-example/internal/config"
	"go-oidc-example/internal/repository"
	"go-oidc-example/internal/router"
)

func init() {
	gob.Register(webauthn.SessionData{})
}

func main() {
	// 1. Load Config
	cfg, err := config.LoadAppConfig("config.json") // assume running from root
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	config.Current = *cfg // Set Global for handlers

	// 2. Init Repository
	repository.Init()

	// 3. Init Auth / Sessions
	auth.Store = sessions.NewFilesystemStore("./.sessions", []byte("super-secret-key"))
	auth.Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("CLIENT_SECRET environment variable is required")
	}

	// 4. Init WebAuthn
	auth.WAuth, err = webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.WebAuthn.RPDisplayName,
		RPID:          cfg.WebAuthn.RPID,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
	})
	if err != nil {
		log.Fatal("Failed to create WebAuthn config:", err)
	}

	// 5. Init OIDC
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		log.Fatalf("Failed to query provider: %v", err)
	}

	auth.OAuth2Config = oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	auth.Verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	auth.CCConfig = &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: clientSecret,
		TokenURL:     cfg.IssuerURL + "/protocol/openid-connect/token",
	}

	// 6. Setup Routes
	router.SetupRoutes(cfg)

	// 7. Start Server
	log.Printf("Server starting on http://localhost:3010")
	log.Fatal(http.ListenAndServe(":3010", nil))
}
