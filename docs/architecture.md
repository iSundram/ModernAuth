## Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                     API Gateway / Load Balancer                  │
│               (TLS termination, WAF rules, rate limiting)        │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Stateless Auth API Servers (Go)                │
│        (Business logic, token issuance, validation, admin)       │
└─────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
    ┌───────────────────────┐       ┌───────────────────────┐
    │      PostgreSQL       │       │         Redis         │
    │   (Primary datastore) │       │ (Sessions, caches)    │
    └───────────────────────┘       └───────────────────────┘
```
