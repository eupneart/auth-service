# Authentication Overview

This document explains the authentication system in the auth-service project, including how users authenticate, how tokens are generated and validated, and how the system maintains security.

## Table of Contents

1. [Authentication Flow](#authentication-flow)
2. [JWT Token System](#jwt-token-system)
3. [User Registration](#user-registration)
4. [User Login (Authentication)](#user-login-authentication)
5. [Token Generation](#token-generation)
6. [Token Validation](#token-validation)
7. [Token Refresh](#token-refresh)
8. [Protected Routes](#protected-routes)
9. [Password Workflows](#password-workflows)
10. [Security Considerations](#security-considerations)
11. [Error Handling](#error-handling)
12. [Database Schema](#database-schema)

---

## Authentication Flow

The authentication system follows this high-level flow:

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION FLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. USER REGISTRATION                                           │
│     POST /register                                              │
│     ├─ Validate email format                                    │
│     ├─ Hash password with bcrypt (cost: 12)                     │
│     ├─ Create user in database                                  │
│     └─ Return user_id and email                                 │
│                                                                 │
│  2. USER LOGIN (AUTHENTICATION)                                 │
│     POST /authenticate                                          │
│     ├─ Find user by email                                       │
│     ├─ Verify password hash                                     │
│     ├─ Update last_login timestamp                              │
│     ├─ Generate access & refresh tokens                         │
│     └─ Return tokens with user info                             │
│                                                                 │
│  3. PROTECTED REQUEST                                           │
│     GET /me                                                     │
│     ├─ Auth middleware receives Bearer token                    │
│     ├─ Validate JWT signature                                   │
│     ├─ Check token expiration                                   │
│     ├─ Extract claims (user_id, role)                           │
│     ├─ Add claims to request context                            │
│     └─ Handler processes request with user context              │
│                                                                 │
│  4. TOKEN REFRESH                                               │
│     POST /refresh                                               │
│     ├─ Validate refresh token                                   │
│     ├─ Check if token revoked in database                       │
│     ├─ Generate new access token                                │
│     └─ Return new access token                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## JWT Token System

The authentication system uses **JWT (JSON Web Tokens)** with **HMAC-SHA256** signing algorithm.

### Token Structure

A JWT consists of three parts separated by dots: `header.payload.signature`

**Example Token:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Breakdown:**
1. **Header**: Contains algorithm (HS256) and token type (JWT)
2. **Payload**: Contains claims (data)
3. **Signature**: HMAC-SHA256 hash of header + payload signed with JWT_SECRET

### Two Token Types

#### 1. Access Token
- **Purpose**: Short-lived token for accessing protected resources
- **Duration**: 15 minutes (900 seconds)
- **Claims**:
  ```json
  {
    "sub": "123",           // user_id (subject)
    "email": "user@example.com",
    "role": "user",         // or "admin"
    "iat": 1234567890,      // issued at
    "exp": 1234568790       // expires at (iat + 900s)
  }
  ```
- **Usage**: Sent in `Authorization: Bearer {token}` header for each request

#### 2. Refresh Token
- **Purpose**: Long-lived token for obtaining new access tokens
- **Duration**: 7 days (604800 seconds)
- **Claims**:
  ```json
  {
    "sub": "123",           // user_id
    "email": "user@example.com",
    "role": "user",         // included for consistency
    "iat": 1234567890,
    "exp": 1235172690       // iat + 604800s
  }
  ```
- **Storage**: Token metadata stored in database for revocation support
- **Usage**: Used to obtain new access tokens without re-authentication

### Token Generation Process

Located in `internal/services/token.go`:

```go
// GenerateTokens creates both access and refresh tokens for a user
func (s *TokenService) GenerateTokens(userID int64, email, role string) (*models.TokenPair, error) {
    now := time.Now()
    
    // Create claims (shared between both tokens)
    claims := jwt.MapClaims{
        "sub":   userID,
        "email": email,
        "role":  role,
        "iat":   now.Unix(),
    }
    
    // Access token (15 minutes)
    accessClaims := jwt.MapClaims{...claims, "exp": now.Add(15 * time.Minute).Unix()}
    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, _ := accessToken.SignedString(s.jwtSecret)
    
    // Refresh token (7 days)
    refreshClaims := jwt.MapClaims{...claims, "exp": now.Add(7 * 24 * time.Hour).Unix()}
    refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
    refreshTokenString, _ := refreshToken.SignedString(s.jwtSecret)
    
    // Store refresh token metadata in database
    s.tokenRepo.Create(&models.TokenMetadata{
        UserID:    userID,
        Token:     refreshTokenString,
        ExpiresAt: expiresAt,
        RevokedAt: nil,
    })
    
    return &models.TokenPair{
        AccessToken:  accessTokenString,
        RefreshToken: refreshTokenString,
    }, nil
}
```

---

## User Registration

**Endpoint:** `POST /register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "secure_password_123"
}
```

**Process:**
1. Handler receives registration request
2. Validates email format using regex
3. Validates password non-empty and minimum length (8 characters)
4. Service calls repository to create user
5. Repository hashes password with bcrypt (cost: 12)
6. User stored in database with `role = "user"` and `active = true`
7. Return user_id and email

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "role": "user",
  "created_at": "2026-05-01T10:30:00Z"
}
```

**Error Cases:**
- Invalid email format → `400 Bad Request`
- Empty or short password → `400 Bad Request`
- Email already exists → `409 Conflict`
- Database error → `500 Internal Server Error`

---

## User Login (Authentication)

**Endpoint:** `POST /authenticate`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "secure_password_123"
}
```

**Process:**
1. Handler validates email and password fields are provided
2. Validates email format
3. Service calls repository to find user by email
4. Repository queries database for user record
5. **If user not found** → Return error (user not registered)
6. **If user is inactive** → Return error (account disabled)
7. **Compare provided password with stored hash** using bcrypt
8. **If password incorrect** → Return error
9. **If password correct**:
   - Update user's `last_login` timestamp
   - Generate access and refresh tokens via TokenService
   - Log successful authentication
   - Return both tokens and user info

**Response (Success):**
```json
{
  "user": {
    "id": 1,
    "email": "user@example.com",
    "role": "user",
    "last_login": "2026-05-01T10:35:00Z"
  },
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900
  }
}
```

**Error Cases:**
- Missing email or password → `400 Bad Request`
- Invalid email format → `400 Bad Request`
- User not found → `401 Unauthorized`
- User inactive → `401 Unauthorized`
- Incorrect password → `401 Unauthorized`
- Database error → `500 Internal Server Error`

**Code Location:** `internal/api/handlers/auth.go` - `Authenticate()` function

---

## Token Generation

Handled by `TokenService` in `internal/services/token.go`.

### GenerateTokens

Creates both access and refresh tokens for a user:

```go
func (s *TokenService) GenerateTokens(userID int64, email, role string) (*models.TokenPair, error)
```

**Parameters:**
- `userID`: User's unique identifier
- `email`: User's email address
- `role`: User's role ("user" or "admin")

**Returns:**
- Access token (15 min expiry)
- Refresh token (7 days expiry)
- Error if generation fails

**Security Details:**
- Uses HMAC-SHA256 algorithm
- JWT_SECRET from environment variable
- Timestamps in Unix format
- Claims include user_id, email, and role

---

## Token Validation

Handled by middleware and TokenService.

### Middleware Validation

**Location:** `internal/api/middleware/auth.go`

`Auth` is a plain function that takes the `TokenService` and returns a
chi-compatible middleware:

```go
func Auth(tokenService services.TokenService) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // 1. Extract Authorization header ("Bearer <token>")
            //    -> 401 if missing or malformed
            // 2. Validate the token with tokenService.ValidateToken(ctx, token)
            //    -> 401 on error / nil claims
            // 3. Reject anything that is not an access token
            //    (claims.TokenType != models.TokenTypeAccess) -> 401
            // 4. Put claims, user ID, and the raw token into the request
            //    context under typed keys
            // 5. next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Handlers read the context via:
//   middleware.GetClaimsFromContext(r)   -> *models.Claims
//   middleware.GetUserIDFromContext(r)   -> int64
//   middleware.GetTokenFromContext(r)    -> (string, error)
```

### ValidateToken

```go
func (s *TokenService) ValidateToken(tokenString string) (jwt.MapClaims, error) {
    // 1. Parse and validate JWT signature
    token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Verify algorithm is HS256
        if token.Method != jwt.SigningMethodHS256 {
            return nil, errors.New("invalid signing method")
        }
        return s.jwtSecret, nil
    })
    
    // 2. Check if parsing successful
    if err != nil || !token.Valid {
        return nil, err
    }
    
    // 3. Extract and return claims
    claims := token.Claims.(jwt.MapClaims)
    
    // 4. Verify required claims exist
    if _, ok := claims["sub"]; !ok {
        return nil, errors.New("missing sub claim")
    }
    
    return claims, nil
}
```

**Validation Steps:**
1. ✅ Token format check (format: `header.payload.signature`)
2. ✅ Signature verification (HMAC-SHA256)
3. ✅ Algorithm verification (must be HS256)
4. ✅ Expiration check (exp claim vs current time)
5. ✅ Required claims check (sub, email, role)

---

## Token Refresh

**Endpoint:** `POST /refresh` (public)

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Process:**
1. Validate refresh token signature and expiration
2. Query database to check if token is revoked
3. If revoked → Return error (user logged out)
4. Generate new access token with same claims
5. Return new access token

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900
}
```

**Why Separate Tokens?**
- **Short access token** reduces exposure if compromised
- **Long refresh token** stored securely on client
- **Refresh token revocation** in DB allows logout
- Users can refresh without re-entering password

---

## Protected Routes

Routes that require authentication use the Auth middleware.

### Middleware Ordering

```go
// Public routes
mux.Post("/register", authHandler.Register)
mux.Post("/authenticate", authHandler.Authenticate)
mux.Post("/refresh", authHandler.Refresh)
mux.Post("/validate", authHandler.Validate)

// Public recovery routes — rate limited per source address
recoveryRoutes := mux.With(authmiddleware.RateLimit(s.passwordLimiter))
recoveryRoutes.Post("/password/forgot", authHandler.ForgotPassword)
recoveryRoutes.Post("/password/reset", authHandler.ResetPassword)

// Protected routes — the auth middleware validates the Bearer token
// and injects claims into the request context
authMiddleware := authmiddleware.Auth(s.TokenService)
protectedRoutes := mux.With(authMiddleware)
protectedRoutes.Post("/logout", authHandler.Logout)
protectedRoutes.Get("/me", authHandler.GetMe)
protectedRoutes.Post("/password/change", authHandler.ChangePassword)
```

### Accessing User Context in Handlers

```go
func GetCurrentUser(w http.ResponseWriter, r *http.Request) {
    // 1. Extract claims from context (added by middleware)
    claims := middleware.GetClaimsFromContext(r)
    
    // 2. Extract user_id from claims
    userID := middleware.GetUserIDFromContext(r)
    
    // 3. Use user context in handler logic
    user, err := userService.GetByID(r.Context(), userID)
    if err != nil {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    
    // 4. Return user data
    json.NewEncoder(w).Encode(user)
}
```

---

## Password Workflows

Three endpoints, all ending in the same place: the password is updated and every
access and refresh token for that user is revoked, so the user must sign in again.

| Endpoint | Auth | Request | Success |
| --- | --- | --- | --- |
| `POST /password/change` | Bearer | `current_password`, `new_password` | `200` |
| `POST /password/forgot` | none | `email` | `202` |
| `POST /password/reset` | none | `token`, `new_password` | `200` |

**Authenticated change.** The user is identified from verified token claims; the
request body carries no user ID, so a caller cannot target another account. A wrong
current password returns `401` and changes nothing. A new password failing the
strength policy returns `400`.

**Forgotten password.** `POST /password/forgot` answers `202` with the same body for
unknown, inactive, and active addresses, and a malformed address returns `400`. The
lookup, token creation, and email are performed after the response is written, so
response time does not reveal whether the account exists. Service failures are logged
and still answered `202` for the same reason.

The emailed token is 32 bytes from `crypto/rand`, base64url-encoded. Only its SHA-256
hash is stored, so the database never holds a usable credential. The link is valid for
`PASSWORD_RESET_TOKEN_LIFETIME` (default 15 minutes) and can be redeemed once.

**Redeeming.** `POST /password/reset` consumes the token atomically. Missing, expired,
and already-used tokens all return the same `400`, so the endpoint cannot be used to
probe which links exist. No access or refresh token is returned: the user signs in with
the new password.

**Write ordering.** All three flows share one sequence — revoke every session,
invalidate outstanding reset tokens, then update the password. There is no enclosing
transaction, so the order carries the guarantee: because the password is written last,
no partial failure can leave a changed password with live sessions.

**Rate limiting.** `/password/forgot` and `/password/reset` are limited to 10 requests
per minute per source address, keyed on `RemoteAddr` rather than `X-Forwarded-For`,
which the caller controls. Independently, reset links are limited to 3 per 15 minutes
per email address; beyond that the request still returns `202` but no mail is sent.
Both limits are in-memory and per process.

**Configuration.** `PASSWORD_RESET_BASE_URL` is the page reset links point at and is
required in production. It is never derived from request headers, which would allow
reset-link poisoning. Production also requires `SMTP_HOST`, `SMTP_USERNAME`,
`SMTP_PASSWORD`, and `SMTP_FROM`; outside production, links are appended to
`.reset-links.log` instead of being sent.

---

## Security Considerations

### 1. Password Security
- **Algorithm**: bcrypt with cost factor 12
- **Benefits**: Slow hashing prevents brute-force attacks
- **When**: During registration and login
- **Never**: Store plaintext passwords

### 2. JWT Secret Management
- **Required in Production**: `JWT_SECRET` environment variable must be set
- **Never**: Commit JWT_SECRET to repository
- **Length**: Use cryptographically secure random string (32+ characters)
- **Rotation**: Implement secret rotation strategy for security updates

### 3. Token Security
- **Access Token**: Short-lived (15 min) reduces exposure
- **Refresh Token**: Long-lived but stored in database for revocation
- **Signature**: HMAC-SHA256 provides integrity check
- **Storage**: Tokens should be stored securely on client (httpOnly cookies, secure storage)

### 4. HTTPS in Production
- Always use HTTPS to prevent token interception
- Never transmit tokens over unencrypted HTTP

### 5. Input Validation
- Email format validation (RFC 5322)
- Password minimum length (8 characters)
- Prevention of SQL injection via parameterized queries

### 6. Rate Limiting (Future)
- Prevent brute-force login attacks
- Limit failed authentication attempts
- Implement exponential backoff

---

## Error Handling

### Authentication Errors

| Error | Status | Cause | Solution |
|-------|--------|-------|----------|
| Missing credentials | 400 | Empty email or password | Check request body |
| Invalid email format | 400 | Email doesn't match pattern | Provide valid email |
| User not found | 401 | Email not registered | Register new account |
| Password incorrect | 401 | Wrong password provided | Verify credentials |
| User inactive | 401 | Account disabled by admin | Contact support |
| Invalid token | 401 | Token malformed or signature invalid | Re-authenticate |
| Token expired | 401 | Access token > 15 minutes old | Use refresh token |
| Token revoked | 401 | User logged out or token revoked | Re-authenticate |
| Database error | 500 | Connection or query failure | Retry request |

### Logging

All authentication events are logged with `slog` package:

```
// Successful login
INFO    User authenticated successfully user_id=1 email=user@example.com

// Failed login
WARN    Authentication failed reason=invalid_password email=user@example.com

// Token validation
DEBUG   Token validated successfully user_id=1

// Errors
ERROR   Database query failed error=connection refused
```

---

## Database Schema

### users table

```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(60) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    active BOOLEAN DEFAULT true,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Fields:**
- `id`: User's unique identifier
- `email`: Email address (unique constraint)
- `password_hash`: bcrypt hash of password (60 characters for bcrypt)
- `role`: User role ("user" or "admin")
- `active`: Whether account is enabled
- `last_login`: Timestamp of last successful login
- `created_at`: Account creation time
- `updated_at`: Last account modification

### token_metadata table

```sql
CREATE TABLE token_metadata (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Fields:**
- `id`: Token metadata record ID
- `user_id`: User who owns this token
- `token`: Encoded JWT refresh token
- `expires_at`: When token expires
- `revoked_at`: When token was revoked (NULL if not revoked)
- `created_at`: When record created

**Purpose**: Enables token revocation on logout and checking active sessions

---

## Example Request/Response Flows

### Complete Authentication Flow

**1. Register New User**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "secure_pass_123"
  }'
```

Response:
```json
{
  "id": 5,
  "email": "alice@example.com",
  "role": "user",
  "created_at": "2026-05-01T10:30:00Z"
}
```

**2. Login (Get Tokens)**
```bash
curl -X POST http://localhost:8080/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "secure_pass_123"
  }'
```

Response:
```json
{
  "user": {
    "id": 5,
    "email": "alice@example.com",
    "role": "user",
    "last_login": "2026-05-01T10:35:00Z"
  },
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjUsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciIsImlhdCI6MTc0NjE3NjAwMCwiZXhwIjoxNzQ2MTc2OTAwfQ.xxx",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjUsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciIsImlhdCI6MTc0NjE3NjAwMCwiZXhwIjoxNzQ2Nzgwc2EwfQ.yyy",
    "expires_in": 900
  }
}
```

**3. Access Protected Resource with Token**
```bash
curl -X GET http://localhost:8080/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjUsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJyb2xlIjoidXNlciIsImlhdCI6MTc0NjE3NjAwMCwiZXhwIjoxNzQ2MTc2OTAwfQ.xxx"
```

Response:
```json
{
  "id": 5,
  "email": "alice@example.com",
  "role": "user",
  "active": true,
  "last_login": "2026-05-01T10:35:00Z",
  "created_at": "2026-05-01T10:30:00Z"
}
```

**4. Request Without Token**
```bash
curl -X GET http://localhost:8080/me
```

Response:
```json
{
  "error": "missing authorization header"
}
```
Status: 401 Unauthorized

---

## Integration with Middleware

See [MIDDLEWARE_GUIDE.md](MIDDLEWARE_GUIDE.md) for detailed information on:
- How Auth middleware validates tokens
- Context extraction and usage
- Logging of authentication events
- Testing authentication middleware
- Performance considerations

