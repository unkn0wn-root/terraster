# Terraster
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A high-performance, feature-rich Layer 7 (L7) load balancer with a robust and user-friendly admin API.

## Key Features

* Multiple load balancing methods including Round Robin, Weighted Round Robin, and IP Hash
* TLS termination with certificate management
* Path rewriting and service-to-service redirection
* Dynamic configuration via comprehensive Admin API
* Multiple host support on the same port
* HTTP compression
* Certificate expiration notifications via email

## Feature Status

### Load Balancing Algorithms
- ✅ Round Robin
- ✅ Weighted Round Robin
- ✅ Least Connections
- ✅ Weighted Least Connections
- ✅ Response Time Based
- ✅ IP Hash
- ✅ Consistent Hashing
- ✅ Adaptive Load Balancing
- ✅ Sticky session

### Advanced Features
- ✅ Plugin (modules) support to extend proxy functionality
- ✅ SSL/TLS Support
- ✅ Connection Pooling
- ✅ Circuit Breaker
- ✅ Rate Limiting
- ✅ Compression
- ✅ Dynamic Middleware Plug-in
- ✅ Configurable Request Logging
- ✅ Restrict access to API via IPs whitelist
- ✅ Custom Request/Response Headers

### Core Features
- ✅ Health Checking
- ✅ Dynamic Configuration via Admin API
- ✅ Graceful Shutdown

## WIP
- ⏳ WebSocket Support (WIP)
- ⏳ Automatic Certificate Management (WIP)


## Quick Start

### Building from Source

```bash
go build -o terraster cmd/terraster
```

## Configuration Guide

### Configuration Methods

Terraster offers three ways to manage your configuration:

1. **Single Config File**
   - Create a config file anywhere and use the `-config` flag
   - Example: `./terraster -config /path/to/config.yaml`

2. **Default Config**
   - Place `config.yaml` in the root directory
   - Terraster will load it automatically at startup

3. **Multiple Services**
   - Create a directory containing multiple service configs
   - Use the `-services` flag to point to the directory
   - Example: `./terraster -services /path/to/services/`

### Basic Configuration

The minimal configuration requires only three fields:

```yaml
port: 8080
host: "lb.domain.com"
backends:
  - url: http://localhost:8081
  - url: http://localhost:8082
```

### Basic Configuration with Middleware and TLS

This configuration demonstrates TLS termination and basic middleware setup:

```yaml
port: 8080
algorithm: round-robin
host: "lb.domain.com"
backends:
  - url: http://localhost:8081
  - url: http://localhost:8082

# Middleware Configuration
middleware:
  - rate_limit:
      requests_per_second: 100
      burst: 30
  - security:
      hsts: true
      frame_options: DENY
      xss_protection: true

# TLS Configuration (optional)
tls:
  enabled: true
  cert_file: "./certificates/my_cert.pem"
  key_file: "./certificates/my_cert_privatekey.key"
```

### Advanced Configuration

This example demonstrates a comprehensive setup with multiple services, health checks, and advanced features:

```yaml
### GLOBAL CONFIG ###
port: 443

# Global Health Check Configuration
health_check:
  interval: 10s
  timeout: 2s
  path: /health

# Global Middleware Configuration
middleware:
  - rate_limit:
      requests_per_second: 100
      burst: 150
  - security:
      hsts: true
      hsts_max_age: 31536000
      frame_options: DENY
      content_type_options: true
      xss_protection: true
  - circuit_breaker:
      threshold: 5
      timeout: 60s

# Global Connection Pool Settings
connection_pool:
  max_idle: 100
  max_open: 1000
  idle_timeout: 90s

### SERVICES CONFIGURATION ###
services:
  # Backend API Service
  - name: backend-api
    host: internal-api1.local.com
    port: 8455
    log_name: backend-api  # Maps to logger configuration
    headers:               # Custom headers
      request_headers:
        X-Custom-Header: "custom-value"
      response_headers:
        Cache-Control: "no-cache"
      remove_request_headers:
        - User-Agent
        - Accept-Encoding
      remove_response_headers:
        - Server
        - X-Powered-By

    # Service-specific TLS
    tls:
      cert_file: "/path/to/api-cert.pem"
      key_file: "/path/to/api-key.pem"

    # Service-specific middleware (overrides global)
    middleware:
      - rate_limit:
          requests_per_second: 2500
          burst: 500

    # Service-specific health check
    health_check:
      type: "http"
      path: "/"
      interval: "5s"
      timeout: "3s"
      thresholds:
        healthy: 2
        unhealthy: 3

    # Path-based routing
    locations:
      - path: "/api/"
        lb_policy: round-robin
        redirect: "/"
        backends:
          - url: http://internal-api1.local.com:8455
            weight: 5
            max_connections: 1000
            # Backend-specific health check
            health_check:
              type: "http"
              path: "/api_health"
              interval: "4s"
              timeout: "3s"
              thresholds:
                healthy: 1
                unhealthy: 2
          - url: http://internal-api2.local.com:8455
            weight: 3
            max_connections: 800

  # Frontend Service
  - name: frontend
    host: frontend.local.com
    port: 443
    locations:
      - path: "/"
        lb_policy: least_connections
        rewrite: "/frontend/"
        backends:
          - url: http://frontend-1.local.com:3000
            weight: 5
            max_connections: 1000
          - url: http://frontend-2.local.com:3000
            weight: 3
            max_connections: 800

  # HTTP to HTTPS Redirect Service
  - name: frontend_redirect
    host: frontend.local.com
    port: 80
    http_redirect: true
    redirect_port: 443

  # Custom Port Redirect Service
  - name: backend_api_redirect
    host: internal-api1.local.com
    port: 80
    http_redirect: true
    redirect_port: 8455
```

## Logging Configuration

### 1. Default Logger
If no custom logging configuration is provided, Terraster will use the default logger configuration from `log.config.json`. Your services will use the `service_default` logger automatically.

```json
{
  "loggers": {
    "terraster": {
      "level": "debug",
      "outputPaths": ["terraster.log"],
      "errorOutputPaths": ["stderr"],
      "development": false,
      "logToConsole": true
    },
    "service_default": {
      "level": "info",
      "outputPaths": ["service_default.log"],
      "errorOutputPaths": ["service_default_error.log"],
      "development": false,
      "logToConsole": false
    }
  }
}
```

### 2. Single Custom Logger Configuration
Create one custom logging configuration file for all services. Each service can reference a specific logger by name in its configuration.

```json
{
  "loggers": {
    "api-services": {
      "level": "info",
      "outputPaths": ["api-services.log"],
      "errorOutputPaths": ["api-errors.log"],
      "development": false,
      "logToConsole": false,
      "logRotation": {
        "enabled": true,
        "maxSizeMB": 50,
        "maxBackups": 10,
        "maxAgeDays": 30,
        "compress": true
      }
    },
    "frontend-services": {
      "level": "debug",
      "outputPaths": ["frontend.log"],
      "errorOutputPaths": ["frontend-errors.log"],
      "development": true,
      "logToConsole": true
    }
  }
}
```

Use in service configuration:
```yaml
services:
  - name: backend-api
    log_name: api-services  # References logger name from config
    # ... rest of service config

  - name: frontend
    log_name: frontend-services  # References logger name from config
    # ... rest of service config
```

### 3. Separate Logger Configuration Per Service
Create individual log configuration files for each service. Each file must start with the `loggers` key.

`backend-api.log.json`:
```json
{
  "loggers": {
    "backend-api": {
      "level": "info",
      "outputPaths": ["backend-api.log"],
      "errorOutputPaths": ["backend-api-error.log"],
      "development": false,
      "logToConsole": false
    }
  }
}
```

`frontend.log.json`:
```json
{
  "loggers": {
    "frontend": {
      "level": "debug",
      "outputPaths": ["frontend.log"],
      "errorOutputPaths": ["frontend-error.log"],
      "development": true,
      "logToConsole": true
    }
  }
}
```

### Running Terraster with Different Logging Configurations

```bash
# Using default logger
./terraster --config config.yaml

# Using single custom log config
./terraster --config config.yaml --log_configs custom.log.json

# Using separate log configs for each service
./terraster --config config.yaml --log_configs backend-api.log.json,frontend.log.json

# Using default logger and appending additional loggers
./terraster --config config.yaml --log_configs additional.log.json
```

#### Important Notes:
- All log config files must start with the `loggers` key
- When using multiple config files, make sure logger names are unique
- If no log_name is specified in service configuration, the service will use the `service_default` logger
- You can append additional loggers to the default configuration by providing them via --log_configs

## Admin API Setup

### Database Configuration

1. Create or use the provided API configuration file:

```yaml
api:
  enabled: true
  host: lb-api.domain.com
  port: 8081
  tls:
    cert_file: "./certs/admin.pem"
    key_file: "./certs/admin_key.key"
  insecure: false # set it ONLY to true if you want to run your API via HTTP (unsecure, NOT RECOMMENDED)
  allowed_ips:    # allow access to API only from those IP addresses (if not defined - no restrictions)
    - 10.10.10.10

database:
  path: "./api.db"

auth:
  jwt_secret: "YourSecretKey"
  token_cleanup_interval: "7h"
  password_expiry_days: 3
```

2. Create an admin user:

```bash
go run scripts/database/api_util.go --config ./api.config.yaml \
  -username "lb_admin" \
  -password "SecurePassword123" \
  -role "admin"
```

### API Examples

#### Get Backend Status
```bash
curl http://localhost:8081/api/backends \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "Content-Type: application/json"
```

#### Add Backend
```bash
curl -X POST http://localhost:8081/api/backends?service_name=backend-api \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "url": "http://newbackend:8080",
    "weight": 5
  }'
```

## Docker Deployment

### Dockerfile
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o terraster cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/terraster .
COPY config.yaml .

EXPOSE 8080 8081 9090
CMD ["./terraster", "--config", "config.yaml"]
```

### Docker Compose
```yaml
version: '3.8'

services:
  terraster:
    build: .
    ports:
      - "8080:8080"
      - "8081:8081"
      - "9090:9090"
    volumes:
      - ./config.yaml:/root/config.yaml
      - ./certs:/etc/certs
    restart: unless-stopped
```

## Benchmarking

A benchmarking script is included in the `tools/benchmark` directory. Run it with:

```bash
go run tools/benchmark/main.go -url http://localhost:8080 -c 10 -n 1000
```

Available flags:
- `-url`: Target URL (default: "http://localhost:8080")
- `-c`: Number of concurrent requests (default: 10)
- `-n`: Total number of requests (default: 1000)
- `-d`: Duration of the test (e.g., "30s", "5m")
