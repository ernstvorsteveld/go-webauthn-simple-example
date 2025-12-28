package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/oauth2"

	"go-oidc-example/internal/auth"
	"go-oidc-example/internal/config"
	"go-oidc-example/internal/models"
	"go-oidc-example/internal/repository"
)

// Context Key
type contextKey string

const UserAttributesKey contextKey = "user_attributes"

// Middleware to extract attributes and bind to context
// WithUserAttributes is a middleware that inspects the session and binds user attributes to the context.
// It checks for "user_id" in the session, retrieves the user from the repository, and selectively
// extracts claims based on the configured mapping for the authentication method (OIDC or WebAuthn).
func WithUserAttributes(next http.HandlerFunc, cfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := auth.Store.Get(r, "session-v2")
		userID, ok := session.Values["user_id"].(string)
		if !ok {
			next(w, r)
			return
		}

		user, exists := repository.GetUser(userID)
		if !exists || user.Claims == "" {
			next(w, r)
			return
		}

		// Determine Auth Method
		authMethod, _ := session.Values["auth_method"].(string)
		var mapping []string
		if authMethod == "webauthn" {
			mapping = cfg.AttributeMapping.WebAuthn
		} else {
			// Default to OIDC or fallback
			mapping = cfg.AttributeMapping.OIDC
		}

		var claims map[string]interface{}
		if err := json.Unmarshal([]byte(user.Claims), &claims); err != nil {
			log.Printf("Failed to unmarshal claims for context: %v", err)
			next(w, r)
			return
		}

		extracted := make(map[string]interface{})
		for _, path := range mapping {
			val := getNestedValue(claims, path)
			if val != nil {
				extracted[path] = val
			}
		}

		// Inject Auth Method
		extracted["auth_method"] = authMethod

		ctx := context.WithValue(r.Context(), UserAttributesKey, extracted)
		next(w, r.WithContext(ctx))
	}
}

func getNestedValue(data map[string]interface{}, path string) interface{} {
	keys := splitPath(path)
	var current interface{} = data
	for _, key := range keys {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[key]
		if current == nil {
			return nil
		}
	}
	return current
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}
	parts = append(parts, path[start:])
	return parts
}

// HandleHome renders the landing page.
func HandleHome(w http.ResponseWriter, r *http.Request) {
	renderLogin(w, "")
}

// HandleLogin processes a username/password login attempt using the "Resource Owner Password Credentials" flow.
// It authenticates against Keycloak, verifies the ID token, and establishes a local session.
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	ctx := r.Context()

	// Exchange credentials for token
	oauth2Token, err := auth.OAuth2Config.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		renderLogin(w, "Invalid username or password")
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field", http.StatusInternalServerError)
		return
	}

	idToken, err := auth.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	canonicalUsername := claims.PreferredUsername
	if canonicalUsername == "" {
		canonicalUsername = claims.Email
	}

	// Create or Get User
	user, exists := repository.GetUser(canonicalUsername)
	if !exists {
		user = &models.User{
			ID:       []byte(canonicalUsername),
			Username: canonicalUsername,
		}
		repository.SaveUser(user)
	}

	// Create Session
	var allClaims map[string]interface{}
	idToken.Claims(&allClaims)
	claimsJSON, _ := json.Marshal(allClaims)

	user.Claims = string(claimsJSON)
	repository.SaveUser(user) // Save Updated Claims

	session, _ := auth.Store.Get(r, "session-v2")
	session.Values["user_id"] = user.Username
	session.Values["auth_method"] = "oidc"
	session.Save(r, w)

	http.Redirect(w, r, "/user", http.StatusSeeOther)
}

// HandleUser renders the user profile page.
// It retrieves the authenticated user from the session and displays their attributes and claims.
func HandleUser(w http.ResponseWriter, r *http.Request) {
	if attrs := r.Context().Value(UserAttributesKey); attrs != nil {
		log.Printf("CONTEXT PROPAGATION SUCCESS: %+v", attrs)
	}
	session, _ := auth.Store.Get(r, "session-v2")
	userID, ok := session.Values["user_id"].(string)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	user, exists := repository.GetUser(userID)
	if !exists {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	claimsStr := user.Claims

	var obj interface{}
	if err := json.Unmarshal([]byte(claimsStr), &obj); err == nil {
		if b, err := json.MarshalIndent(obj, "", "  "); err == nil {
			claimsStr = string(b)
		}
	}

	// NOTE: Templates path might change depending on where binary is run
	// For now assuming run from root
	tmpl, err := template.ParseFiles("templates/user.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	contextAttrsStr := ""
	if attrs := r.Context().Value(UserAttributesKey); attrs != nil {
		if b, err := json.MarshalIndent(attrs, "", "  "); err == nil {
			contextAttrsStr = string(b)
		}
	}

	data := struct {
		Email             string
		Claims            string
		ContextAttributes string
	}{
		Email:             userID,
		Claims:            claimsStr,
		ContextAttributes: contextAttrsStr,
	}
	tmpl.Execute(w, data)
}

// HandleLogout clears the session and redirects the user to the home page.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.Store.Get(r, "session-v2")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleWebAuthnRegisterBegin initiates the WebAuthn registration process.
// It generates a new credential creation options object and saves the session state.
func HandleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	log.Println("Endpoint /webauthn/register/begin hit")
	session, _ := auth.Store.Get(r, "session-v2")
	userID, ok := session.Values["user_id"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, _ := repository.GetUser(userID)

	authSelect := protocol.AuthenticatorSelection{
		UserVerification: protocol.VerificationPreferred,
	}

	att := r.URL.Query().Get("attachment")
	if att == "platform" {
		authSelect.AuthenticatorAttachment = protocol.Platform
	} else if att == "cross-platform" {
		authSelect.AuthenticatorAttachment = protocol.CrossPlatform
	}

	rk := r.URL.Query().Get("resident_key")
	if rk == "required" {
		authSelect.ResidentKey = protocol.ResidentKeyRequirementRequired
		authSelect.RequireResidentKey = protocol.ResidentKeyRequired()
	} else if rk == "preferred" {
		authSelect.ResidentKey = protocol.ResidentKeyRequirementPreferred
	} else {
		authSelect.ResidentKey = protocol.ResidentKeyRequirementDiscouraged
	}

	uv := r.URL.Query().Get("user_verification")
	if uv == "required" {
		authSelect.UserVerification = protocol.VerificationRequired
	} else if uv == "discouraged" {
		authSelect.UserVerification = protocol.VerificationDiscouraged
	}

	options, sessionData, err := auth.WAuth.BeginRegistration(
		user,
		webauthn.WithAuthenticatorSelection(authSelect),
		webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
	)
	if err != nil {
		log.Printf("Error in BeginRegistration: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["webauthn_session"] = sessionData
	session.Save(r, w)

	json.NewEncoder(w).Encode(options)
}

// HandleWebAuthnRegisterFinish completes the WebAuthn registration process.
// It verifies the authenticator's attestation response and stores the new credential.
func HandleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.Store.Get(r, "session-v2")
	userID, ok := session.Values["user_id"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	user, _ := repository.GetUser(userID)

	sessionDataVal, ok := session.Values["webauthn_session"]
	if !ok {
		http.Error(w, "No registration session", http.StatusBadRequest)
		return
	}

	sessionData, ok := sessionDataVal.(webauthn.SessionData)
	if !ok {
		http.Error(w, "Invalid session data", http.StatusInternalServerError)
		return
	}

	credential, err := auth.WAuth.FinishRegistration(user, sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user.Credentials = append(user.Credentials, *credential)
	repository.SaveUser(user)
	fmt.Printf("✅ Registered Credential for user %s\n", user.Username)

	json.NewEncoder(w).Encode("Registration Success")
}

// HandleCheckPasskey checks if a given user has any registered WebAuthn credentials.
// This is used by the frontend to conditionally show the "Login with Passkey" button.
func HandleCheckPasskey(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}
	user, exists := repository.GetUser(username)
	hasPasskey := exists && len(user.Credentials) > 0

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"hasPasskey": hasPasskey})
}

// HandleWebAuthnLoginBegin initiates the WebAuthn login assertion process (passwordless).
// It generates a challenge for the user to sign with their authenticator.
func HandleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	user, exists := repository.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	options, sessionData, err := auth.WAuth.BeginLogin(user)
	if err != nil {
		log.Printf("Error in BeginLogin: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, _ := auth.Store.Get(r, "session-v2")
	session.Values["webauthn_session"] = sessionData
	session.Values["login_username"] = username
	session.Save(r, w)

	json.NewEncoder(w).Encode(options)
}

// HandleWebAuthnLoginFinish completes the WebAuthn login process.
// It verifies the assertion signature. critically, it also syncs the user's latest data
// (roles, groups) from Keycloak using a service account (Client Credentials flow).
func HandleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	session, _ := auth.Store.Get(r, "session-v2")

	sessionDataVal, ok := session.Values["webauthn_session"]
	if !ok {
		http.Error(w, "No login session", http.StatusBadRequest)
		return
	}
	sessionData, ok := sessionDataVal.(webauthn.SessionData)
	if !ok {
		http.Error(w, "Invalid session data", http.StatusInternalServerError)
		return
	}

	loginUsername, ok := session.Values["login_username"].(string)
	if !ok {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	user, exists := repository.GetUser(loginUsername)
	if !exists {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	credential, err := auth.WAuth.FinishLogin(user, sessionData, r)
	if err != nil {
		http.Error(w, "Login failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	_ = credential

	// Sync Config need to be passed or accessed.
	// We can't access main.Config directly.
	// Ideally we pass config to Handlers or SyncKeycloakUser.
	// Use auth.SyncKeycloakUser(user.Username, ???)
	// We haven't injected Config into handlers yet!
	// Quick fix: Assume we load config in main and pass it or set a global in config package (not ideal but works for refactor).
	// Or change SyncKeycloakUser to not need config if we set CCConfig globally.
	// Auth.SyncKeycloakUser uses cfg.AdminBaseURL...
	// Let's assume we can modify Auth.SyncKeycloakUser to use a global or passed cfg.
	// I'll leave a TODO or fix it by dependency injection.
	// For now, I will modify the handler to not call SyncKeycloakUser OR passing it if I can access it.
	// Actually, I can put `AppConfig` in `config` package as a global `Current`?
	// Let's do `config.LoadAppConfig` in main, then `config.Current = cfg`.

	freshClaims, errSync := auth.SyncKeycloakUser(user.Username, &config.Current)
	if errSync == nil {
		user.Claims = freshClaims
		repository.SaveUser(user)
	} else {
		log.Printf("Warning: Failed to sync: %v", errSync)
	}

	session.Values["user_id"] = user.Username
	session.Values["auth_method"] = "webauthn"
	delete(session.Values, "webauthn_session")
	delete(session.Values, "login_username")
	session.Save(r, w)

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "redirect": "/user"})
}

func renderLogin(w http.ResponseWriter, errMsg string) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct{ Error string }{Error: errMsg}
	tmpl.Execute(w, data)
}

// HandleSSOLogin initiates the OIDC authorization code flow.
// It redirects the user to Keycloak. If "action=register" is passed, it hints Keycloak to start the WebAuthn registration flow.
func HandleSSOLogin(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	io.ReadFull(rand.Reader, b)
	state := base64.URLEncoding.EncodeToString(b)

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})

	var opts []oauth2.AuthCodeOption
	if r.URL.Query().Get("action") == "register" {
		opts = append(opts, oauth2.SetAuthURLParam("kc_action", "webauthn-register-passwordless"))
	}

	url := auth.OAuth2Config.AuthCodeURL(state, opts...)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleSSOCallback processes the OIDC callback from Keycloak.
// It exchanges the authorization code for an ID Token, validates it, and establishes a local session.
func HandleSSOCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("oauth_state")
	if err != nil || r.URL.Query().Get("state") != cookie.Value {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	ctx := r.Context()
	oauth2Token, err := auth.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token", http.StatusInternalServerError)
		return
	}
	idToken, err := auth.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	idToken.Claims(&claims)

	canonicalUsername := claims.PreferredUsername
	if canonicalUsername == "" {
		canonicalUsername = claims.Email
	}

	user, exists := repository.GetUser(canonicalUsername)
	if !exists {
		user = &models.User{
			ID:       []byte(canonicalUsername),
			Username: canonicalUsername,
		}
		repository.SaveUser(user)
	}

	var allClaims map[string]interface{}
	idToken.Claims(&allClaims)
	claimsJSON, _ := json.Marshal(allClaims)
	user.Claims = string(claimsJSON)
	repository.SaveUser(user)

	session, _ := auth.Store.Get(r, "session-v2")
	session.Values["user_id"] = user.Username
	session.Values["auth_method"] = "oidc"
	session.Save(r, w)

	http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}
