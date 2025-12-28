package config

import (
	"encoding/json"
	"os"
)

var Current AppConfig

// AppConfig holds the application configuration
type AppConfig struct {
	ClientID     string `json:"client_id"`
	IssuerURL    string `json:"issuer_url"`
	AdminBaseURL string `json:"admin_base_url"`
	RedirectURL  string `json:"redirect_url"`
	WebAuthn     struct {
		RPDisplayName string   `json:"rp_display_name"`
		RPID          string   `json:"rp_id"`
		RPOrigins     []string `json:"rp_origins"`
	} `json:"webauthn"`
	AttributeMapping struct {
		OIDC     []string `json:"oidc"`
		WebAuthn []string `json:"webauthn"`
	} `json:"attribute_mapping"`
}

// LoadAppConfig reads and parses the JSON configuration file from the specified path.
// It returns a pointer to the AppConfig struct or an error if the file cannot be read/parsed.
func LoadAppConfig(path string) (*AppConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg AppConfig
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
