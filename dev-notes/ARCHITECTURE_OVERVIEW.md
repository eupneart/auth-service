# Auth Service Architecture Overview

A comprehensive guide to understanding how the Auth Service project works, its architecture, and data flows.

## Table of Contents

- [System Overview](#system-overview)
- [Architecture Diagram](#architecture-diagram)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Authentication Flow](#authentication-flow)
- [Authorization Model](#authorization-model)
- [Technology Stack](#technology-stack)
- [Design Patterns](#design-patterns)
- [Database Design](#database-design)
- [Request/Response Cycle](#requestresponse-cycle)
- [Error Handling](#error-handling)
- [Security Implementation](#security-implementation)

---

## System Overview

Auth Service is a microservice designed to handle all authentication and authorization requirements for the EupneArt ecosystem. It operates as a standalone service that other applications can interact with via HTTP endpoints.

### Purpose

The service provides:
- User account management (registration, profile)
- Authentication (login, password verification)
- Token generation (JWT-based access and refresh tokens)
- Token validation and revocation
- Session management

### Scope (V1)

**What it does:**
- Accept user registrations with email and password
- Authenticate users with credentials
- Generate JWT tokens for authenticated sessions
- Refresh access tokens and validate tokens (for service-to-service checks)
- Revoke tokens on logout via authentication middleware
- Expose the current user (`GET /me`) on protected routes
- Store user profiles and authentication data
- Manage token metadata and revocation

**What it does NOT do (V1.1+):**
- Email verification
- Rate limiting outside the password recovery endpoints
- Multi-factor authentication
- OAuth2/OpenID Connect
- Refresh token rotation
- Multi-device session management

---

## Architecture Diagram

```
                          CLIENT APPLICATION
                               (Frontend)
                                  |
                    HTTP/HTTPS    |
                                  v
                    ┌─────────────────────────┐
                    │   Chi HTTP Router       │
                    │  (Port 8080 default)    │
                    └──────────────┬──────────┘
                                   |
                ┌──────────────────┼──────────────────┐
                |                  |                  |
                v                  v                  v
          /register          /authenticate          /ping
         (POST handler)       (POST handler)      (Heartbeat)
                |                  |
                └──────────────────┴──────────────────┐
                                   |
                    ┌──────────────────────────────┐
                    │  Auth Handler Layer          │
                    │  (Request Processing)        │
                    └──────────────┬───────────────┘
                                   |
                    ┌──────────────────────────────┐
                    │  Service Layer               │
                    │  (Business Logic)            │
                    │                              │
                    │  - UserService              │
                    │  - TokenService             │
                    └──────────────┬───────────────┘
                                   |
                    ┌──────────────────────────────┐
                    │  Repository Layer            │
                    │  (Data Access)               │
                    │                              │
                    │  - UserRepo                 │
                    │  - TokenRepo                │
                    └──────────────┬───────────────┘
                                   |
                    ┌──────────────────────────────┐
                    │  PostgreSQL Database         │
                    │                              │
                    │  - users table              │
                    │  - token_metadata table     │
                    └──────────────────────────────┘
```

---

## Core Components

### 1. HTTP Router (Chi)

**File:** `internal/api/routes.go`

The entry point for all HTTP requests. Uses Chi router to define endpoints and middleware.

```
Public routes:
- GET  /ping                   (Health check)
- POST /register               (User registration)
- POST /authenticate           (User login)
- POST /refresh                (Token refresh)
- POST /validate               (Token validation)

Public routes, rate limited per source address:
- POST /password/forgot        (Request a reset link; always 202)
- POST /password/reset         (Redeem a reset token)

Protected routes (require Bearer access token via auth middleware):
- POST /logout                 (Revoke the current token)
- GET  /me                     (Get current user)
- POST /password/change        (Change password with the current one)
```

**Responsibilities:**
- Define HTTP routes
- Apply middleware (CORS, logging)
- Wrap protected routes with the authentication middleware
  (`internal/api/middleware/auth.go`, `middleware.Auth(tokenService)`), which
  validates the Bearer token and puts the claims / user ID / token in the
  request context
- Route requests to appropriate handlers

### 2. Handler Layer

**File:** `internal/api/handlers/auth.go`

HTTP request handlers that receive requests, validate input, and coordinate service calls.

**Handlers:**
- `Authenticate()`: Handles login requests
- `Register()`: Handles user registration requests

**Responsibilities:**
- Parse and validate HTTP request bodies
- Call appropriate service methods
- Format and return HTTP responses
- Handle HTTP status codes
- Log important events

**Example Flow:**
```
HTTP Request
    |
    v
Parse JSON Body
    |
    v
Validate Input
    |
    v
Call UserService
    |
    v
Format Response
    |
    v
Send HTTP Response
```

### 3. Service Layer

**Files:** 
- `internal/services/user.go`
- `internal/services/token.go`

Business logic layer that implements authentication and token management rules.

#### UserService

**Responsibilities:**
- User CRUD operations
- Password hashing and verification
- User validation
- Database transactions

**Key Methods:**
- `Insert(user)`: Create new user with hashed password
- `GetByEmail(email)`: Find user by email
- `PasswordMatches(user, plainText)`: Verify password
- `Update(user)`: Update user fields
- `ResetPassword(user)`: Change user password

**Flow:**
```
User Data
    |
    v
Validate
    |
    v
Hash Password (bcrypt)
    |
    v
Call Repository
    |
    v
Return User/Error
```

#### TokenService

**Responsibilities:**
- JWT token generation
- Token validation
- Token revocation
- Token metadata management

**Key Methods:**
- `GenerateTokens(user)`: Create access and refresh tokens
- `ValidateToken(tokenStr)`: Verify token signature and claims
- `RefreshAccessToken(refreshToken)`: Generate new access token
- `RevokeToken(tokenStr)`: Mark token as revoked
- `RevokeAllTokensForUser(userID)`: Revoke all user tokens

**Token Structure:**
```
JWT Token Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

JWT Token Payload (Claims):
{
  "user_id": 123,
  "email": "user@example.com",
  "role": "user",
  "token_type": "access",
  "exp": 1609459200,
  "iat": 1609459200,
  "iss": "eupneart-auth-service",
  "sub": "123"
}
```

### 4. Repository Layer

**Files:**
- `internal/repositories/user.go`
- `internal/repositories/token.go`

Data access layer that handles all database operations.

#### UserRepository

**Responsibilities:**
- Execute SQL queries for users
- Map database rows to User models
- Handle database errors

**Methods:**
- `GetAll()`: Fetch all users
- `GetByID(id)`: Find user by ID
- `GetByEmail(email)`: Find user by email
- `Insert(user)`: Create new user
- `Update(user)`: Modify user
- `DeleteByID(id)`: Remove user

#### TokenRepository

**Responsibilities:**
- Store token metadata
- Track token revocation
- Manage token lifecycle

**Methods:**
- `SaveTokenMetadata(metadata)`: Store token info
- `GetTokenMetadata(tokenID)`: Retrieve token data
- `IsTokenRevoked(tokenID)`: Check revocation status
- `RevokeToken(tokenID)`: Mark as revoked
- `RevokeAllTokensForUser(userID)`: Revoke user's tokens
- `CleanupExpiredTokens()`: Remove old tokens

### 5. Models

**File:** `internal/models/`

Data structures that represent domain objects.

**User Model:**
```go
type User struct {
    ID        int64
    Email     string
    FirstName string
    LastName  string
    Password  string (hashed)
    Role      string
    IsActive  bool
    CreatedAt time.Time
    UpdatedAt time.Time
    LastLogin time.Time
}
```

**Token Models:**
```go
type Claims struct {
    UserID    int64
    Email     string
    Role      string
    TokenType string
    // ... JWT standard claims
}

type TokenMetadata struct {
    ID        string
    UserID    int64
    TokenType string
    IsRevoked bool
    CreatedAt time.Time
    ExpiresAt time.Time
    LastUsedAt time.Time
}

type TokenResponse struct {
    AccessToken      string
    RefreshToken     string
    TokenType        string
    ExpiresIn        int64
    RefreshExpiresIn int64
}
```

### 6. Database Connection

**File:** `internal/db/db.go`

Manages PostgreSQL connection pooling and retry logic.

**Features:**
- Automatic retry on connection failure (10 attempts)
- Connection pooling (reusable connections)
- Health check (ping) before returning connection
- Exponential backoff between retries

### 7. Configuration Management

**File:** `pkg/env/env.go`

Loads and manages environment-based configuration.

**Variables:**
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `JWT_SECRET`, `JWT_ISSUER`
- `APP_PORT`, `APP_ENV` (development/production)
- `JWT_ACCESS_TOKEN_DURATION`, `JWT_REFRESH_TOKEN_DURATION`

**Loading Logic:**
```
1. Check APP_ENV variable
2. Load .env.{APP_ENV} file
3. Fall back to .env if specific file not found
4. Override with system environment variables
5. Apply defaults
```

### 8. Utilities

**Files:**
- `utils/validation.go`: Input validation
- `utils/json.go`: JSON serialization/deserialization

**Validation:**
- Email format validation
- Password strength requirements (min 8 chars, mixed case, number, special char)
- Name format validation

---

## Data Flow

### User Registration Flow

```
1. CLIENT REQUEST
   POST /register
   {
     "first_name": "John",
     "last_name": "Doe",
     "email": "john@example.com",
     "password": "SecurePass123!"
   }

2. HANDLER (auth.Register)
   - Parse JSON body
   - Validate input fields (empty check)
   - Call UserService.Insert()

3. SERVICE (user_service.Insert)
   - Validate email format
   - Validate password strength
   - Hash password with bcrypt (cost 12)
   - Call UserRepo.Insert()

4. REPOSITORY (user_repo.Insert)
   - Execute INSERT SQL query
   - Return generated user ID

5. TOKEN GENERATION (token_service.GenerateTokens)
   - Create JWT access token claims
   - Create JWT refresh token claims
   - Sign tokens with JWT_SECRET
   - Generate unique token IDs
   - Save token metadata to database

6. RESPONSE
   {
     "error": false,
     "message": "User registered successfully",
     "data": {
       "access_token": "eyJhbGc...",
       "refresh_token": "eyJhbGc...",
       "token_type": "Bearer",
       "expires_in": 900
     }
   }
```

### User Login Flow

```
1. CLIENT REQUEST
   POST /authenticate
   {
     "email": "john@example.com",
     "password": "SecurePass123!"
   }

2. HANDLER (auth.Authenticate)
   - Parse JSON body
   - Validate input (not empty)
   - Call UserService.GetByEmail()

3. SERVICE (user_service.GetByEmail)
   - Call UserRepo.GetByEmail()

4. REPOSITORY (user_repo.GetByEmail)
   - Execute SELECT query with email parameter
   - Return User object

5. SERVICE (user_service.PasswordMatches)
   - Use bcrypt.CompareHashAndPassword()
   - Compare provided password with stored hash

6. TOKEN GENERATION (token_service.GenerateTokens)
   - Create access token (15 min expiry)
   - Create refresh token (7 days expiry)
   - Store token metadata in database

7. DATABASE UPDATE
   - Update user.last_login timestamp

8. RESPONSE
   {
     "error": false,
     "message": "Successfully authenticated",
     "data": {
       "access_token": "eyJhbGc...",
       "refresh_token": "eyJhbGc...",
       "token_type": "Bearer",
       "expires_in": 900,
       "refresh_expires_in": 604800
     }
   }
```

### Token Validation Flow

```
1. CLIENT REQUEST
   POST /validate
   {
     "token": "eyJhbGc..."
   }

   HANDLER (auth.Validate)
   - Reads the token from the JSON body
   - On an invalid token, still returns HTTP 200 with {"valid": false, "error": ...}

2. TOKEN SERVICE (ValidateToken)
   - Parse JWT with signature verification
   - Check signature is HMAC-SHA256
   - Verify signature with JWT_SECRET
   - Extract and validate claims
   - Check token is not expired
   - Check token is not revoked

3. REPOSITORY (IsTokenRevoked)
   - Execute SELECT is_revoked FROM token_metadata
   - Return revocation status

4. RESPONSE (if valid)
   {
     "error": false,
     "message": "Token is valid",
     "data": {
       "valid": true,
       "claims": {
         "user_id": 123,
         "email": "user@example.com",
         "role": "user",
         "expires_at": "2026-04-26T16:20:16Z"
       }
     }
   }
```

---

## Authentication Flow

### How Authentication Works

```
┌─────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION SEQUENCE                   │
└─────────────────────────────────────────────────────────────┘

1. USER PROVIDES CREDENTIALS
   └─ Email and password sent to /authenticate

2. CREDENTIAL VERIFICATION
   ├─ Look up user by email
   ├─ If not found -> reject
   └─ If found -> verify password

3. PASSWORD VERIFICATION
   ├─ Get stored bcrypt hash from database
   ├─ Use bcrypt.CompareHashAndPassword()
   ├─ If not match -> reject
   └─ If match -> continue

4. TOKEN GENERATION
   ├─ Create access token payload
   │  ├─ user_id
   │  ├─ email
   │  ├─ role
   │  ├─ token_type: "access"
   │  ├─ exp: now + 15 minutes
   │  └─ iat: now
   │
   └─ Create refresh token payload
      ├─ user_id
      ├─ email
      ├─ token_type: "refresh"
      ├─ exp: now + 7 days
      └─ iat: now

5. TOKEN SIGNING
   ├─ Use HMAC-SHA256 algorithm
   ├─ Sign with JWT_SECRET
   └─ Produce JWT string

6. TOKEN METADATA STORAGE
   ├─ Generate unique token ID
   ├─ Store in token_metadata table
   ├─ Mark as not revoked
   ├─ Store expiry time
   └─ Store creation time

7. RETURN TOKENS
   └─ Send access and refresh tokens to client
```

### Token Structure

```
Access Token (15 minutes):
- Used for API requests
- Contains user info and role
- Short-lived for security

Refresh Token (7 days):
- Used to get new access token
- Longer-lived
- Stored securely by client
- Never sent in headers (in body only)

JWT Format:
[Header].[Payload].[Signature]

Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "user_id": 123,
  "email": "user@example.com",
  "role": "user",
  "token_type": "access",
  "iss": "eupneart-auth-service",
  "exp": 1609459200,
  "iat": 1609459200,
  "jti": "unique-token-id"
}

Signature:
HMACSHA256(
  base64url(header) + "." +
  base64url(payload),
  JWT_SECRET
)
```

---

## Authorization Model

### User Roles

Currently, Auth Service supports basic role-based authorization:

```
Roles:
- "user"  (default role for new registrations)
- "admin" (seeded in database, see migration 006)

Role Seeding:
Migration 006_seed_admin_user creates:
- Email: admin@eupneart.local
- Role: admin
- Used for testing and initial setup
```

### Role Validation

In the Claims structure:
```go
type Claims struct {
    Role string `json:"role"`  // Included in both access and refresh tokens
}
```

This role is stored in the JWT token and can be validated by other services:
- Other microservices receive the token
- They decode it (no validation needed if just reading claims)
- They check the `role` field to authorize actions

---

## Technology Stack

### Backend

```
Go 1.23.1
- Language for entire service
- Statically typed, compiled
- Fast execution, small binary

Chi v5 Router
- HTTP routing framework
- Lightweight, fast
- Built-in middleware support

PostgreSQL
- Relational database
- Handles users and token metadata
- ACID transactions
- Connection pooling support

JWT (golang-jwt/jwt v5)
- Token generation and validation
- HMAC-SHA256 signing
- Standard JWT implementation

bcrypt
- Password hashing
- Automatic salt generation
- Adjustable cost factor (12)
```

### Infrastructure

```
PostgreSQL 12+
- Database server
- Persistent data storage

Docker
- Containerization
- Environment isolation
- Easy deployment

Docker Compose
- Multi-container orchestration
- Local development
- Service management
```

### Development Tools

```
Go Modules
- Dependency management
- Version pinning

Testify
- Testing framework
- Assertion helpers

SQLMock
- SQL mocking for tests
- Database abstraction testing
```

---

## Design Patterns

### 1. Layered Architecture

```
┌─────────────────┐
│   API Layer     │ (HTTP Handlers)
├─────────────────┤
│  Service Layer  │ (Business Logic)
├─────────────────┤
│ Repository Layer│ (Data Access)
├─────────────────┤
│ Database Layer  │ (PostgreSQL)
└─────────────────┘
```

**Benefits:**
- Separation of concerns
- Easy to test each layer
- Easy to replace implementations
- Clear dependencies

### 2. Dependency Injection

Services receive dependencies through constructors:

```go
// Instead of creating dependencies inside
func NewUserService(userRepo repositories.UserRepoInterface) *UserService {
    return &UserService{userRepo: userRepo}
}

// This allows:
// - Easy testing (mock repositories)
// - Flexibility (swap implementations)
// - Loose coupling (interfaces not concrete types)
```

### 3. Interface-Based Design

Repositories and services use interfaces:

```go
type UserRepoInterface interface {
    GetAll(ctx context.Context) ([]*models.User, error)
    GetByID(ctx context.Context, id int64) (*models.User, error)
    GetByEmail(ctx context.Context, email string) (*models.User, error)
    Insert(ctx context.Context, u models.User) (int64, error)
    Update(ctx context.Context, u models.User) error
    DeleteByID(ctx context.Context, id int64) error
}

type TokenService interface {
    GenerateTokens(ctx context.Context, user *models.User) (string, string, error)
    ValidateToken(ctx context.Context, token string) (*models.Claims, error)
    RefreshAccessToken(ctx context.Context, refreshToken string) (string, error)
    RevokeToken(ctx context.Context, token string) error
    // ... more methods
}
```

**Benefits:**
- Easy to mock for testing
- Easy to create alternative implementations
- Clear contracts

### 4. Context-Based Cancellation

All operations accept context for timeout and cancellation:

```go
func (s *UserService) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    // Create timeout context
    ctx, cancel := context.WithTimeout(ctx, dbTimeout)
    defer cancel()  // Clean up
    
    // Use context for database operations
    return s.userRepo.GetByEmail(ctx, email)
}
```

**Benefits:**
- Timeout protection (prevent hanging requests)
- Request cancellation (stop work if client disconnects)
- Resource cleanup

### 5. Error Wrapping

Errors include context for debugging:

```go
if err != nil {
    return fmt.Errorf("inserting user: %w", err)
}
```

**Benefits:**
- Maintains error chain
- Can identify where error occurred
- Easy to debug

---

## Database Design

### Schema Overview

```
┌─────────────────────────────────────────┐
│              users                      │
├─────────────────────────────────────────┤
│ id (BIGSERIAL PRIMARY KEY)              │
│ email (VARCHAR UNIQUE)                  │
│ first_name (VARCHAR)                    │
│ last_name (VARCHAR)                     │
│ password (VARCHAR - bcrypt hash)        │
│ role (VARCHAR)                          │
│ is_active (BOOLEAN)                     │
│ created_at (TIMESTAMP)                  │
│ updated_at (TIMESTAMP)                  │
│ last_login (TIMESTAMP)                  │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│         token_metadata                  │
├─────────────────────────────────────────┤
│ id (VARCHAR PRIMARY KEY - UUID)         │
│ user_id (BIGINT FOREIGN KEY)            │
│ token_type (VARCHAR)                    │
│ device_id (VARCHAR)                     │
│ client_id (VARCHAR)                     │
│ is_revoked (BOOLEAN)                    │
│ created_at (TIMESTAMP)                  │
│ expires_at (TIMESTAMP)                  │
│ last_used_at (TIMESTAMP)                │
└─────────────────────────────────────────┘
```

### Table Relationships

```
users (1) ──────> (many) token_metadata
         via user_id
```

### Key Design Decisions

1. **User ID as BIGSERIAL**
   - Allows large number of users
   - Auto-increment for convenience

2. **Password as TEXT (Hashed)**
   - Never store plain text
   - bcrypt hashes are ~60 characters

3. **Token Metadata Table**
   - Track token lifecycle
   - Support revocation
   - Track usage patterns

4. **Separate Timestamps**
   - created_at: When token issued
   - expires_at: When token expires
   - last_used_at: Track usage

---

## Request/Response Cycle

### HTTP Request Lifecycle

```
1. CLIENT SENDS REQUEST
   ├─ HTTP method (GET, POST, etc.)
   ├─ URL path
   ├─ Headers
   └─ Body (JSON)

2. ROUTER (Chi)
   ├─ Match route to handler
   ├─ Apply middleware (CORS, logging)
   └─ Call handler function

3. HANDLER
   ├─ Read and parse request body
   ├─ Validate input format
   ├─ Call service layer
   └─ Format response

4. SERVICE
   ├─ Validate business rules
   ├─ Call repository layer
   ├─ Perform business logic
   └─ Return result or error

5. REPOSITORY
   ├─ Create context with timeout
   ├─ Execute SQL query
   ├─ Map database rows to objects
   └─ Return result or error

6. HANDLER (return path)
   ├─ Check for errors
   ├─ Set HTTP status code
   ├─ Serialize response to JSON
   └─ Send to client

7. CLIENT RECEIVES RESPONSE
   ├─ HTTP status code
   ├─ Headers (Content-Type, etc.)
   └─ Body (JSON)
```

### Response Format

All responses follow a consistent format:

```json
{
  "error": false,
  "message": "Human-readable message",
  "data": {
    "/* response-specific data */"
  }
}
```

### Error Responses

```json
{
  "error": true,
  "message": "Error description"
}
```

---

## Error Handling

### Error Types

```
1. VALIDATION ERRORS
   - Invalid input format
   - Missing required fields
   - Invalid email format
   - Weak password
   
   HTTP Status: 400 Bad Request

2. AUTHENTICATION ERRORS
   - Invalid credentials
   - User not found
   - Wrong password
   - Account deactivated
   
   HTTP Status: 401 Unauthorized

3. CONFLICT ERRORS
   - Email already exists
   - Duplicate user
   
   HTTP Status: 409 Conflict

4. DATABASE ERRORS
   - Connection failed
   - Query failed
   - Constraint violation
   
   HTTP Status: 500 Internal Server Error

5. TOKEN ERRORS
   - Invalid token
   - Expired token
   - Revoked token
   - Wrong token type
   
   HTTP Status: 401 Unauthorized
```

### Error Flow

```
Error Occurs
    |
    v
Log with slog
├─ Error message
├─ Context (user_id, email, etc.)
├─ File and method name
└─ Stack trace (if applicable)
    |
    v
Check Error Type
    |
    ├─> Validation Error ──> HTTP 400
    ├─> Auth Error ────────> HTTP 401
    ├─> Conflict Error ────> HTTP 409
    └─> Server Error ──────> HTTP 500
    |
    v
Format JSON Response
├─ error: true
├─ message: description
└─ (no data field)
    |
    v
Send to Client
```

### Error Logging

All errors are logged with context:

```go
slog.Error("failed to get user by email",
    "error", err,
    "email", email,
    "method", "UserService.GetByEmail")
```

This creates structured logs for easy analysis.

---

## Security Implementation

### Password Security

```
1. HASHING
   - Algorithm: bcrypt
   - Cost factor: 12
   - Salt: automatic per password

2. STORAGE
   - Only hash stored, never plain text
   - ~60 character bcrypt string

3. VERIFICATION
   - Use bcrypt.CompareHashAndPassword()
   - Compare plain text with stored hash
   - Return boolean (match/no match)

4. VALIDATION
   - Minimum 8 characters
   - Mix of uppercase and lowercase
   - Include number
   - Include special character
```

### JWT Token Security

```
1. GENERATION
   - Algorithm: HMAC-SHA256
   - Secret: JWT_SECRET environment variable
   - Payload: user info + expiry

2. STORAGE
   - Access token: Short-lived (15 min)
   - Refresh token: Longer-lived (7 days)
   - Never store in database (except metadata)

3. VALIDATION
   - Check signature with JWT_SECRET
   - Verify expiry time
   - Check revocation status in database

4. REVOCATION
   - Token marked as revoked in database
   - Future validations will reject
```

### SQL Injection Prevention

```
All database queries use parameterized statements:

SAFE:
    query := "SELECT * FROM users WHERE id = $1"
    row := db.QueryRowContext(ctx, query, userID)

UNSAFE (NOT USED):
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", userID)
    row := db.QueryRowContext(ctx, query)

Why parameterized:
- User input never concatenated into SQL
- Database driver handles escaping
- Prevents SQL injection attacks
```

### Input Validation

```
1. FORMAT VALIDATION
   - Email: RFC 5321 compliant
   - Password: strength requirements
   - Names: alphanumeric + spaces/hyphens/apostrophes

2. LENGTH VALIDATION
   - Email: 3-254 characters
   - Password: 8-72 bytes (bcrypt's input limit)
   - Names: 1-100 characters

3. REQUIRED FIELD VALIDATION
   - No empty fields
   - No null values for required data
```

### CORS Configuration

```
CORS controls which origins can access the API:

AllowedOrigins:
  - https://eupneart.com (production)
  - http://localhost:4200 (frontend dev)
  - http://localhost:8080 (backend dev)

Methods: GET, POST, PUT, DELETE, OPTIONS
Headers: Accept, Authorization, Content-Type, X-CSRF-Token
Credentials: Allowed
MaxAge: 5 minutes
```

---

## How to Trace a Request

### Tracing a Registration Request

```
1. Client sends:
   POST /register
   {"first_name": "John", "last_name": "Doe", 
    "email": "john@example.com", "password": "Pass123!"}

2. Chi Router matches /register route
   └─> Calls auth.Register()

3. Handler receives request:
   - utils.ReadJSON() reads and parses body
   - Validates all fields present
   - auth.Register() continues

4. Handler calls UserService.Insert():
   - Checks field formats (email, password, names)
   - bcrypt.GenerateFromPassword() hashes password
   - user_repo.Insert() creates database record

5. Repository executes SQL:
   INSERT INTO users (email, first_name, last_name, password, ...)
   VALUES ($1, $2, $3, $4, ...)

6. UserService receives new user ID
   └─> Calls UserService.GetByID() to fetch full user

7. TokenService.GenerateTokens() is called:
   - Creates access token (15 min expiry)
   - Creates refresh token (7 days expiry)
   - Signs both with JWT_SECRET
   - Stores metadata in token_metadata table

8. Handler formats response:
   {
     "error": false,
     "message": "User registered successfully",
     "data": {
       "access_token": "eyJ...",
       "refresh_token": "eyJ...",
       "token_type": "Bearer",
       "expires_in": 900
     }
   }

9. Client receives response with 201 status code

10. Logs generated at each step:
    - "User validation started"
    - "Password hashed successfully"
    - "User inserted successfully" 
    - "Tokens generated"
    - "User registered successfully"
```

---

## Summary

### What Happens During Registration

1. User submits email, password, and name
2. Service validates all inputs
3. Password is hashed with bcrypt
4. User record is stored in database
5. JWT tokens are generated (access + refresh)
6. Token metadata is stored for revocation tracking
7. Tokens are returned to user
8. User is logged in automatically

### What Happens During Login

1. User submits email and password
2. Service looks up user by email
3. Password is verified using bcrypt
4. User record is retrieved from database
5. JWT tokens are generated
6. Token metadata is stored
7. Last login timestamp is updated
8. Tokens are returned to user

### Key Security Points

1. Passwords are never stored in plain text (bcrypt)
2. Tokens are signed and validated (JWT)
3. All SQL uses parameterized queries (no injection)
4. Input is validated before processing
5. Errors don't expose sensitive information
6. All operations have timeout protection

### Architecture Benefits

1. Clean separation of concerns (layers)
2. Easy to test (interfaces and DI)
3. Easy to scale (microservice pattern)
4. Easy to understand (clear structure)
5. Easy to modify (loosely coupled)

---

**For more details, see:**
- README.md: Setup and usage instructions
- PROGRESS.md: Status and known issues (original review archived under archived/)
- ANALYSIS_MISSING_FEATURES.md: Planned features

**Last Updated:** 2026-09-06
