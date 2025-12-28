# Go WebAuthn Simple Example

This project demonstrates a robust integration of **WebAuthn (Passkeys)** into a Go web application, featuring both Consumer (Embedded) and Enterprise (SSO) authentication flows. It is integrated with **Keycloak** acting as an Identity Provider (IdP) and Service Account provider.

## Features

-   **Dual Authentication Flows**:
    -   **Consumer**: Direct login via Username/Password or Passkey.
    -   **Enterprise**: SSO Login via Keycloak (OIDC), supporting Passkey via redirect.
-   **Passkey Management**:
    -   Registration of new Passkeys (TouchID, FaceID, YubiKey).
    -   Conditional UI (Autofill support).
-   **Keycloak Integration**:
    -   Standard OIDC Login.
    -   Service Account Synchronization (fetching Roles/Groups even for local Passkey login).
    -   Enterprise-initiated Passkey Registration.
-   **Architecture**:
    -   Standard Go Project Layout (`cmd`, `internal`).
    -   In-memory user store (persisted to JSON).

## Prerequisites

-   **Go 1.20+**
-   **Docker & Docker Compose**
-   **Make** (optional)

## Setup

1.  **Start Dependencies (Keycloak & Postgres)**
    ```bash
    docker compose up -d
    ```

2.  **Configure Keycloak**
    -   Access Admin Console: `http://localhost:8080` (admin/admin).
    -   Create a Realm (e.g., `myrealm`).
    -   Create a Client (e.g., `go-webauthn`).
        -   Valid Redirect URIs: `http://localhost:3010/*`
        -   Web Origins: `http://localhost:3010`
        -   **Enable Service Accounts**: Turn on "Service Accounts Enabled".
    -   Copy `Client Secret`.

3.  **Environment Configuration**
    Set the client secret in your environment:
    ```bash
    export CLIENT_SECRET="your-client-secret-from-keycloak"
    ```
    *Ensure `config.json` matches your Keycloak settings (Client ID, Issuer URL).*

4.  **Run the Application**
    ```bash
    go run ./cmd/server
    ```
    Server will start at `http://localhost:3010`.

## Directory Structure

```text
.
├── cmd/
│   └── server/       # Application Entrypoint
├── internal/
│   ├── auth/         # Keycloak (OIDC) & WebAuthn Logic
│   ├── config/       # Configuration Loading
│   ├── handlers/     # HTTP Handlers
│   ├── models/       # Data Structures (User, Credential)
│   ├── repository/   # Data Persistence (users.json)
│   └── router/       # Route Definitions
├── templates/        # HTML Templates
└── docker-compose.yaml
```
