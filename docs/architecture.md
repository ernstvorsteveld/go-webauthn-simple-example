# System Architecture

## Overview
This document explains the WebAuthn (Passkey) flow implemented in the application, detailing how the Frontend, Backend, and Database interact to provide passwordless login.

## 1. Package Design (Standard Go Layout)
The application was refactored from a flat structure to a clean, component-based design:

-   **`cmd/server`**: The entry point. Initializes Config, DB, Auth providers, and starts the HTTP server.
-   **`internal/auth`**: Centralizes Authentication logic.
    -   Holds global `WebAuthn` and `OIDC` provider instances.
    -   Contains `SyncKeycloakUser` for Service Account synchronization.
-   **`internal/repository`**: Handles data persistence. Currently uses a JSON file (`users.json`) but abstracts the storage behind `GetUser`/`SaveUser` functions.
-   **`internal/handlers`**: Contains all HTTP handler logic.
    -   Uses `auth` package for logic.
    -   Uses `repository` package for data.

## 2. Authentication Flows

### A. Consumer Flow (Embedded)
-   **Password**: Standard Form POST. Validates credentials against Keycloak (Resource Owner Password Flow - ROPC).
-   **Passkey**:
    1.  **Check**: Frontend queries `/auth/check-passkey` on blur.
    2.  **Begin**: `/webauthn/login/begin` returns challenge.
    3.  **Sign**: Browser signs challenge (TouchID/FaceID).
    4.  **Finish**: `/webauthn/login/finish` verifies signature.
    5.  **Sync**: Backend calls Keycloak (Service Account) to fetch latest roles/claims.

### B. Enterprise Flow (Redirect)
-   **SSO Login**: Redirects user to Keycloak (`/sso/login` -> Keycloak -> `/callback`).
-   **Registration**: `/sso/login?action=register` triggers a special Keycloak flow (`kc_action=webauthn-register-passwordless`) to double-check identity before allowing credential registration.

## 3. Data Model
*   **Users**: Stored in `users.json`.
*   **Key**: `preferred_username` (e.g., `demo-user`).
*   **Credentials**: WebAuthn Public Keys stored inside the User record.

## 4. Sequence Diagrams

### Conditional Passkey Login
```mermaid
sequenceDiagram
    actor User
    participant FE as Frontend
    participant BE as Backend
    participant DB as Repository

    User->>FE: Enters Username
    FE->>BE: GET /auth/check-passkey
    BE->>DB: Check if user has credentials
    BE->>FE: { "hasPasskey": true }
    
    User->>FE: Clicks "Login with Passkey"
    FE->>BE: GET /webauthn/login/begin
    BE->>FE: Challenge
    FE->>User: TouchID Prompt
    User->>FE: Biometric Auth
    FE->>BE: POST /webauthn/login/finish (Signature)
    BE->>BE: Verify Signature
    BE-->>User: Success
```

### Service Account Sync
Even when logging in with a local Passkey, we ensure enterprise security policies (roles) are applied.

```mermaid
sequenceDiagram
    participant IDP as Keycloak
    participant BE as Backend
    
    Note over BE: User Logged in via Passkey
    BE->>IDP: Client Credentials Request (Service Account)
    IDP-->>BE: Access Token
    BE->>IDP: GET /users/{id}/role-mappings
    IDP-->>BE: Current Roles
    BE->>BE: Update Local Session Claims
    BE->>BE: Update Local Session Claims
```

## 5. Data Persistence Model

This diagram illustrates "What is stored where" across the system components.

```mermaid
graph TD
    subgraph Browser ["Frontend (Browser)"]
        Cookies[("Cookies (Secure)")]
        subgraph Auth ["Authenticator (Secure Element)"]
            PrivKey["Private Key (Passkey)"]
            Count["Sign Counter"]
        end
    end

    subgraph App ["Go Application Server"]
        Filesystem[("Filesystem")]
        Sessions["/sessions (Gob Encoded)"]
        Users["/users.json"]
        
        Filesystem --> Sessions
        Filesystem --> Users
        
        Users -- Contains --> PubKey["Public Key"]
        Users -- Contains --> CredID["Credential ID"]
        Users -- Contains --> UserID["User Handle (UUID)"]
    end

    subgraph IdP ["Keycloak (Identity Provider)"]
        KC_DB[("Keycloak Database")]
        KC_DB -- Contains --> Passwords["User Passwords"]
        KC_DB -- Contains --> Roles["Roles & Realms"]
        KC_DB -- Contains --> FedID["Federated Identities"]
    end

    Browser -- "Session Cookie (Ref)" --> Sessions
    Sessions -- "Refers to" --> Users
    Users -- "Synced from" --> IdP
```
