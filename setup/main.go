package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Config
const (
	AdminURL      = "http://localhost:8080"
	AdminUser     = "admin"
	AdminPassword = "admin123"
	RealmName     = "demo-realm"
	ClientID      = "go-oidc-client"
	TestUser      = "demo-user"
	TestPassword  = "password123"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

type ClientRepresentation struct {
	ID                           string   `json:"id,omitempty"`
	ClientID                     string   `json:"clientId"`
	Enabled                      bool     `json:"enabled"`
	RedirectURIs                 []string `json:"redirectUris"`
	DirectAccessGrantsEnabled    bool     `json:"directAccessGrantsEnabled"`
	StandardFlowEnabled          bool     `json:"standardFlowEnabled"`
	PublicClient                 bool     `json:"publicClient"`
	ServiceAccountsEnabled       bool     `json:"serviceAccountsEnabled"`
	AuthorizationServicesEnabled bool     `json:"authorizationServicesEnabled"`
	ClientAuthenticatorType      string   `json:"clientAuthenticatorType"`
}

type CredentialRepresentation struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func main() {
	// 1. Get Admin Token
	token, err := getAdminToken()
	if err != nil {
		log.Fatalf("Failed to get admin token: %v\nIs Keycloak running?", err)
	}
	fmt.Println("✅ Authenticated as Admin")

	// 2. Create Realm
	createRealm(token)

	// 3. Create Client
	createClient(token)

	// 4. Get Client Secret
	secret := getClientSecret(token)
	fmt.Printf("\n🎉 Setup Complete!\n")
	fmt.Printf("==============================================\n")
	fmt.Printf("Realm:         %s\n", RealmName)
	fmt.Printf("Client ID:     %s\n", ClientID)
	fmt.Printf("Client Secret: %s\n", secret)
	fmt.Printf("Test User:     %s\n", TestUser)
	fmt.Printf("Test Password: %s\n", TestPassword)
	fmt.Printf("==============================================\n")
	fmt.Printf("\nExport this to run your app:\n")
	fmt.Printf("export CLIENT_SECRET=%s\n", secret)

	// 5. Create User
	createUser(token)
}

func getAdminToken() (string, error) {
	data := fmt.Sprintf("username=%s&password=%s&grant_type=password&client_id=admin-cli", AdminUser, AdminPassword)
	req, err := http.NewRequest("POST", AdminURL+"/realms/master/protocol/openid-connect/token", strings.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status: %d", resp.StatusCode)
	}

	var result TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

func createRealm(token string) {
	realm := fmt.Sprintf(`{"id": "%s", "realm": "%s", "enabled": true}`, RealmName, RealmName)
	req, _ := http.NewRequest("POST", AdminURL+"/admin/realms", strings.NewReader(realm))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 409) {
		log.Printf("Failed to create realm (might already exist): %v", resp.Status)
	} else {
		fmt.Println("✅ Realm created (or exists)")
	}
}

func createClient(token string) {
	client := ClientRepresentation{
		ClientID:                  ClientID,
		Enabled:                   true,
		RedirectURIs:              []string{"http://localhost:3010/*"},
		DirectAccessGrantsEnabled: true,
		StandardFlowEnabled:       true,
		PublicClient:              false, // Confidential client for server-side
		ClientAuthenticatorType:   "client-secret",
	}

	body, _ := json.Marshal(client)
	req, _ := http.NewRequest("POST", AdminURL+"/admin/realms/"+RealmName+"/clients", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return
	}

	if resp.StatusCode == 409 {
		// Client exists, let's update it
		fmt.Println("⚠️ Client exists, updating configuration...")

		// Get client ID first
		reqID, _ := http.NewRequest("GET", AdminURL+"/admin/realms/"+RealmName+"/clients?clientId="+ClientID, nil)
		reqID.Header.Set("Authorization", "Bearer "+token)
		respID, _ := http.DefaultClient.Do(reqID)
		var clients []ClientRepresentation
		json.NewDecoder(respID.Body).Decode(&clients)

		if len(clients) > 0 {
			id := clients[0].ID
			client.ID = id // Make sure ID is set for update
			body, _ := json.Marshal(client)
			reqUpdate, _ := http.NewRequest("PUT", AdminURL+"/admin/realms/"+RealmName+"/clients/"+id, strings.NewReader(string(body)))
			reqUpdate.Header.Set("Authorization", "Bearer "+token)
			reqUpdate.Header.Set("Content-Type", "application/json")
			respUpdate, _ := http.DefaultClient.Do(reqUpdate)
			if respUpdate.StatusCode == 204 {
				fmt.Println("✅ Client updated")
			} else {
				log.Printf("Failed to update client: %v", respUpdate.Status)
			}
		}
	} else if resp.StatusCode == 201 {
		fmt.Println("✅ Client created")
	} else {
		log.Printf("Failed to create client: %v", resp.Status)
	}
}

func getClientSecret(token string) string {
	// Need to get the internal ID of the client first
	req, _ := http.NewRequest("GET", AdminURL+"/admin/realms/"+RealmName+"/clients?clientId="+ClientID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	var clients []ClientRepresentation
	json.NewDecoder(resp.Body).Decode(&clients)
	if len(clients) == 0 {
		log.Fatal("Could not find client")
	}
	id := clients[0].ID

	// Now get the secret
	req, _ = http.NewRequest("GET", AdminURL+"/admin/realms/"+RealmName+"/clients/"+id+"/client-secret", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)

	var creds CredentialRepresentation
	json.NewDecoder(resp.Body).Decode(&creds)
	return creds.Value
}

func createUser(token string) {
	user := fmt.Sprintf(`{"username": "%s", "enabled": true, "email": "test@example.com", "firstName": "Test", "lastName": "User", "credentials": [{"type": "password", "value": "%s", "temporary": false}]}`, TestUser, TestPassword)
	req, _ := http.NewRequest("POST", AdminURL+"/admin/realms/"+RealmName+"/users", strings.NewReader(user))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 409) {
		log.Printf("Failed to create user (might already exist): %v", resp.Status)
	} else {
		fmt.Println("✅ User created")
	}
}
