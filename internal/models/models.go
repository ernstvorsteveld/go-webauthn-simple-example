package models

import "github.com/go-webauthn/webauthn/webauthn"

// User represents the user model stored in the database
type User struct {
	ID          []byte                `json:"ID"`
	Username    string                `json:"Username"`
	Credentials []webauthn.Credential `json:"Credentials"`
	Claims      string                `json:"Claims"` // JSON string
}

// WebAuthn User Interface Implementation
func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Username }
func (u *User) WebAuthnDisplayName() string                { return u.Username }
func (u *User) WebAuthnIcon() string                       { return "" }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
