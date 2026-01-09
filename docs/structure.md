## Project Structure
```
/cmd/auth-server          # Main application entrypoint
/internal
  /api/http               # HTTP handlers and middleware
  /auth                   # Core authentication flows
  /storage                # Storage interfaces and implementations
    /pg                   # PostgreSQL implementation
    /redis                # Redis implementation
  /utils                  # Utilities (crypto, time, etc.)
/config                   # Configuration files
/scripts/migrations       # Database migrations
```
