package router

import (
	"net/http"

	"go-oidc-example/internal/config"
	"go-oidc-example/internal/handlers"
)

// SetupRoutes registers all HTTP handlers for the application.
// It maps the URL paths to their respective handler functions in the internal/handlers package.
func SetupRoutes(cfg *config.AppConfig) {
	http.HandleFunc("/", handlers.HandleHome)
	http.HandleFunc("/login", handlers.HandleLogin)
	http.HandleFunc("/user", handlers.WithUserAttributes(handlers.HandleUser, cfg))
	http.HandleFunc("/logout", handlers.HandleLogout)

	// WebAuthn Registration
	http.HandleFunc("/webauthn/register/begin", handlers.HandleWebAuthnRegisterBegin)
	http.HandleFunc("/webauthn/register/finish", handlers.HandleWebAuthnRegisterFinish)

	// Check if user has passkeys
	http.HandleFunc("/auth/check-passkey", handlers.HandleCheckPasskey)

	// WebAuthn Login
	http.HandleFunc("/webauthn/login/begin", handlers.HandleWebAuthnLoginBegin)
	http.HandleFunc("/webauthn/login/finish", handlers.HandleWebAuthnLoginFinish)

	// Enterprise SSO (Redirect)
	http.HandleFunc("/sso/login", handlers.HandleSSOLogin)
	http.HandleFunc("/callback", handlers.HandleSSOCallback)
}
