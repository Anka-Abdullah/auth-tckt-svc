# AI Coding Agent Instructions for auth-svc-ticketing

## Architecture Overview
This project follows **Clean Architecture** (Hexagonal Architecture) in Go:
- **Core Domain** (`internal/core/domain/`): Business entities (User, Token) with GORM models
- **Ports** (`internal/core/ports/`): Interfaces for external dependencies (repositories, services)
- **Application Layer** (`internal/application/`): Usecases and services orchestrating business logic
- **Infrastructure** (`internal/infrastructure/`): External implementations (HTTP handlers, DB repos, security)
- **Shared Packages** (`pkg/`): Reusable utilities (logger, response utils)

**Data Flow**: HTTP Request → Handler → Usecase → Service → Repository → Database

## Key Patterns & Conventions

### Dependency Injection
- Use `internal/config/container.go` for wiring dependencies
- Interfaces from `ports/` ensure testability and decoupling
- Example: `UserRepo` injected into handlers via container

### Logging
- Structured logging with Zap (`pkg/logger/`)
- Logger attached to context: `logger.WithLogger(ctx, logger)`
- Use `logger.FromContext(ctx)` in handlers/usecases
- Log levels: Info, Error, Warn, Debug with structured fields

### HTTP Layer
- Echo framework with custom middleware stack
- Standard response format (`pkg/utils/response.go`):
  ```go
  type Response struct {
      Success bool        `json:"success"`
      Message string      `json:"message"`
      Data    interface{} `json:"data,omitempty"`
      Error   string      `json:"error,omitempty"`
  }
  ```
- Validation using `github.com/go-playground/validator/v10` on request DTOs

### Database & Models
- GORM with PostgreSQL
- UUID primary keys with `uuid_generate_v4()`
- Soft deletes via `gorm.DeletedAt`
- Models in `domain/` with GORM tags
- Repositories implement `ports/` interfaces

### Authentication & Security
- JWT tokens (access + refresh) via `infrastructure/security/jwt_manager.go`
- Password hashing with bcrypt (in `password_manager.go`)
- Redis for token storage (refresh tokens)
- JWT middleware extracts claims to context

### Error Handling
- Custom domain errors in `core/domain/errors.go`
- HTTP errors mapped in handlers
- Consistent error responses using `utils.ErrorResponse()`

## Developer Workflows

### Running the Service
```bash
go run cmd/api/main.go
```
- Loads config from env vars (`.env` file)
- Initializes container with DB, repos, handlers
- Starts Echo server with middleware

### Database Migrations
- GORM auto-migration in `config/database.go`
- Manual migrations via `scripts/migrate/main.go` (placeholder)

### Testing
- Unit tests in `tests/unit/`
- Integration tests in `tests/integration/`
- Run with `go test ./...`

### Docker & Deployment
- Dockerfile in `deployments/docker/` (placeholder)
- K8s manifests in `deployments/k8s/`

## Code Generation & Tools
- Use `go generate` if needed (none currently)
- Linting: Standard Go tools (`go vet`, `golint`)
- Formatting: `go fmt`

## Important Files
- `cmd/api/main.go`: Application entry point
- `internal/config/container.go`: Dependency injection setup
- `internal/core/domain/user.go`: Primary domain model
- `internal/infrastructure/http/handlers/auth_handler.go`: Auth endpoints
- `pkg/utils/response.go`: Response formatting utilities</content>
<parameter name="filePath">d:\MySelf\go\echo-ticketing\auth-svc-ticketing\.github\copilot-instructions.md