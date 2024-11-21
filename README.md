# Terraster - Uncomplicated Load Balancer/Reverse Proxy

## Project Status: Early Stages 🚧
**This project is currently in its early development stages. While the core functionality is in place and working as intended, further improvements and features are actively being developed. Expect updates as the project evolves.**

A high-performance, feature-rich Layer 7 (L7) load balancer with a robust and user-friendly admin API.

## Features

- Multiple load balancing algorithms
  - [x] Round Robin
  - [x] Weighted Round Robin
  - [x] Least Connections
  - [x] Weighted Least Connections
  - [x] Response Time Based
  - [x] IP Hash
  - [x] Consistent Hashing
  - [x] Adaptive Load Balancing

- Advanced Features
  - [ ] WebSocket Support - WIP
  - [x] SSL/TLS
  - [ ] Automatic certificate management - WIP
  - [x] Connection pooling
  - [x] Circuit breaker
  - [x] Rate limiting
  - [x] Compression
  - [ ] Custom Request Headers
  - [x] Dynamic middleware plug-in
  - [ ] Requests logger file path from config - WIP

- Monitoring
  - [x] Health checking

- Administration
  - [x] Dynamic configuration via Admin API
  - [x] Graceful shutdown

## Quick Start

### Build Terraster:
```bash
go build -o terraster cmd/main.go
```

### Create a configuration file (or use provided in repo):

There are only 3 fields that are required - <b>port, host and backends</b>. Everything else is optional:

```yaml
port: 8080
host: "lb.domain.com"
backends:
  - url: http://localhost:8081
  - url: http://localhost:8082
```

#### Basic Configuration with TLS offloading (load balancer in SSL and backend in HTTP)
```yaml
port: 8080
algorithm: round-robin
host: "lb.domain.com"
backends:
  - url: http://localhost:8081
  - url: http://localhost:8082

middleware:
  - rate_limit:
      requests_per_second: 100
      burst: 30

# this can be omitted/removed or changed to 'false' if you only want your load balancer on http (for any reason)
tls:
  enabled: true
  cert_file: "./certificates/my_cert.pem"
  key_file: "./certificates/my_cert_privatekey.key"
```

#### Advanced Configuration
```yaml
### GLOBAL CONFIG ###
port: 443

# global health check will be used by every service that don't have health_check specified
health_check:
  interval: 10s
  timeout: 2s
  path: /health

# global middlewares enabled for all services
middleware:
  - rate_limit: # global rate limit for each service if not defined in the service
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

connection_pool:
  max_idle: 100
  max_open: 1000
  idle_timeout: 90s


### ADVANCED LOAD BALANCER CONFIG ###
services:
  - name: backend-api # service name
    host: internal-api1.local.com # service listener hostname
    port: 8455 # service listener port
    tls: # service tls configuration
      cert_file: "/path/to/api-cert.pem"
      key_file: "/path/to/api-key.pem"
    # service specific middlewares - will override global
    middleware:
      - rate_limit:
          requests_per_second: 2500
          burst: 500
    # service health check configuration - will be used by each location
    # can be overwrite by location config
    health_check:
      type: "http"
      path: "/"
      interval: "5s"
      timeout: "3s"
      thresholds:
        healthy: 2
        unhealthy: 3
    locations:
      - path: "/api/" # served path suffix so "https://internal-api1.local.com/api/"
        lb_policy: round-robin # load balancing policy
        redirect: "/" # redirect e.q. from "/" to "/api/"
        backends:
          - url: http://internal-api1.local.com:8455
            weight: 5
            max_connections: 1000
            health_check: # or have separate health check for each backend and override service health check
              type: "http"
              path: "/api_health"
              interval: "4s"
              timeout: "3s"
              thresholds:
                healthy: 1
                unhealthy: 2
          - url: http://internal-api2.local.com:8455 # this is missing health check so it will inherit from service
            weight: 3
            max_connections: 800

  - name: frontend
    host: frontend.local.com
    port: 443
    locations:
      - path: "/"
        lb_policy: least_connections
        rewrite: "/frontend/" # rewrite e.q. from "/" to "/frontend/" in the backend service
        backends:
          - url: http://frontend-1.local.com:3000
            weight: 5
            max_connections: 1000

          - url: http://frontend-2.local.com:3000
            weight: 3
            max_connections: 800

  - name: frontend_redirect
    host: frontend.local.com
    port: 80
    # this will redirect to 443 based on host so you can have multiple hosts on the same port
    # but keep in mind that you have to have correct host redirect so this :80 -> frontend.local.com:443
    http_redirect: true
    redirect_port: 443

  - name: backend_api_redirect
    host: internal-api1.local.com
    port: 80
    http_redirect: true
    redirect_port: 8455 # this will redirect to 8455 - mark host field
```

3. Run the load balancer:
```bash
./terraster --config config.yaml
```

## API Examples

### Admin API

1. Database setup
- First, you need to create database configuration file or use provided in repo.
```yaml
api:
  enabled: true
  host: localhost
  port: 8081
  # optional
  tls:
    enabled: true
    cert_file: "./certs/krogsveen-2024-chained-no-key.pem"
    key_file: "./certs/privkey_key.key"

database:
  path: "./api.db"

auth:
  jwt_secret: "HelloFormTheOtherSide"
  token_cleanup_interval: "7h"
  password_expiry_days: 3
```

- Then, create API admin user
```console
go run scripts/database/api_util.go --config ./api.config.yaml -username "lb_admin" -password "Test953.Hello" -role "admin"
```

- Admin API is disabled by default so you need to set 'enabled: true' in API configuration to enable it

2. Get Backend Status:
```bash
curl http://localhost:8081/api/backends \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1..." \
    -H "Content-Type: application/json"
```

3. Add Backend to service:
```bash
curl -X POST http://localhost:8081/api/backends?service_name=backend-api \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1..." \
  -d '{
    "url": "http://newbackend:8080",
    "weight": 5
  }'
```

## Benchmarking Tool

```go
// tools/benchmark/main.go
package main

import (
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:8080", "URL to benchmark")
	concurrency := flag.Int("c", 10, "Number of concurrent requests")
	requests := flag.Int("n", 1000, "Total number of requests")
	duration := flag.Duration("d", 0, "Duration of the test")
	flag.Parse()

	results := make(chan time.Duration, *requests)
	errors := make(chan error, *requests)
	var wg sync.WaitGroup

	start := time.Now()
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	if *duration > 0 {
		timer := time.NewTimer(*duration)
		go func() {
			<-timer.C
			fmt.Println("Duration reached, stopping...")
			*requests = 0
		}()
	}

	// Start workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < *requests / *concurrency; i++ {
				requestStart := time.Now()
				resp, err := client.Get(*url)
				if err != nil {
					errors <- err
					continue
				}
				resp.Body.Close()
				results <- time.Since(requestStart)
			}
		}()
	}

	// Wait for completion
	wg.Wait()
	close(results)
	close(errors)

	// Process results
	var total time.Duration
	var count int
	var min, max time.Duration
	errCount := 0

	for d := range results {
		if min == 0 || d < min {
			min = d
		}
		if d > max {
			max = d
		}
		total += d
		count++
	}

	for range errors {
		errCount++
	}

	// Print results
	fmt.Printf("\nBenchmark Results:\n")
	fmt.Printf("URL: %s\n", *url)
	fmt.Printf("Concurrency Level: %d\n", *concurrency)
	fmt.Printf("Time taken: %v\n", time.Since(start))
	fmt.Printf("Complete requests: %d\n", count)
	fmt.Printf("Failed requests: %d\n", errCount)
	fmt.Printf("Requests per second: %.2f\n", float64(count)/time.Since(start).Seconds())
	fmt.Printf("Mean latency: %v\n", total/time.Duration(count))
	fmt.Printf("Min latency: %v\n", min)
	fmt.Printf("Max latency: %v\n", max)
}
```

## Docker Deployment

```dockerfile
# Dockerfile
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

```yaml
# docker-compose.yml
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

## License

MIT License
