package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"go-oidc-example/internal/config"
)

var (
	WAuth        *webauthn.WebAuthn
	OAuth2Config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
	CCConfig     *clientcredentials.Config
	Store        *sessions.FilesystemStore
)

// SyncKeycloakUser fetches fresh user data from Keycloak
func SyncKeycloakUser(username string, cfg *config.AppConfig) (string, error) {
	ctx := context.Background()
	client := CCConfig.Client(ctx) // Authenticated Service Account Client

	adminBaseURL := cfg.AdminBaseURL

	// 1. Search for user by username
	resp, err := client.Get(fmt.Sprintf("%s/users?username=%s", adminBaseURL, username))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch user: %s", resp.Status)
	}

	var users []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return "", err
	}

	if len(users) == 0 {
		return "", fmt.Errorf("user not found in keycloak")
	}

	userProfile := users[0]
	userID, _ := userProfile["id"].(string)

	// 2. Fetch User Roles (Realm Roles)
	respRoles, err := client.Get(fmt.Sprintf("%s/users/%s/role-mappings/realm", adminBaseURL, userID))
	if err != nil {
		return "", fmt.Errorf("failed to fetch roles: %v", err)
	}
	defer respRoles.Body.Close()

	var roles []map[string]interface{}
	if err := json.NewDecoder(respRoles.Body).Decode(&roles); err != nil {
		return "", fmt.Errorf("failed to decode roles: %v", err)
	}

	var roleNames []string
	for _, r := range roles {
		if name, ok := r["name"].(string); ok {
			roleNames = append(roleNames, name)
		}
	}

	// 3. Construct "ID Token" style JSON
	normalized := map[string]interface{}{
		"sub":                userProfile["id"],
		"username":           userProfile["username"],
		"preferred_username": userProfile["username"],
		"email":              userProfile["email"],
		"given_name":         userProfile["firstName"],
		"family_name":        userProfile["lastName"],
		"name":               fmt.Sprintf("%s %s", userProfile["firstName"], userProfile["lastName"]),
		"email_verified":     userProfile["emailVerified"],
		"realm_access": map[string]interface{}{
			"roles": roleNames,
		},
		"synced_at": time.Now().Format(time.RFC3339),
	}

	userData, _ := json.Marshal(normalized)
	return string(userData), nil
}
