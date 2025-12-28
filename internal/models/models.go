package models

import "github.com/go-webauthn/webauthn/webauthn"

// User represents the user model stored in the database.
// It matches the structure expected by the WebAuthn library and stores
// credentials and OpenID Connect claims.
type User struct {
	ID          []byte                `json:"ID"`
	Username    string                `json:"Username"`
	Credentials []webauthn.Credential `json:"Credentials"`
	Claims      string                `json:"Claims"` // JSON string
}

// WebAuthnID returns the user's unique ID.
func (u *User) WebAuthnID() []byte { return u.ID }

// WebAuthnName returns the user's username.
func (u *User) WebAuthnName() string { return u.Username }

// WebAuthnDisplayName returns the user's display name (same as username here).
func (u *User) WebAuthnDisplayName() string { return u.Username }

// WebAuthnIcon returns the user's icon (not used).
func (u *User) WebAuthnIcon() string { return "" }

// WebAuthnCredentials returns the user's registered WebAuthn credentials.
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
