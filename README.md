# terraster - Uncomplicated Load Balancer

A high-ish-performance, feature-rich (?) HTTP/HTTPS load balancer written in Go with Admin API. 

## Features

- Multiple load balancing algorithms
  - Round Robin
  - Weighted Round Robin
  - Least Connections
  - Weighted Least Connections
  - Response Time Based
  - IP Hash
  - Consistent Hashing
  - Adaptive Load Balancing

- Advanced Features
  - WebSocket Support
  - SSL/TLS with automatic certificate management
  - Connection pooling
  - Circuit breaker
  - Rate limiting
  - Compression

- Monitoring
  - Health checking

- Administration
  - REST API
  - Dynamic configuration
  - Graceful shutdown

## Quick Start

1. Build the load balancer:
```bash
go build -o terraster cmd/main.go
```

2. Create a configuration file or use provided in repo (config.yaml):
```yaml
port: 443
admin_port: 4433

services:
  - name: backend-api # service name
    host: internal-api1.local.com # service listener hostname
    port: 8455 # service listener port
    tls:
      cert_file: "/path/to/api-cert.pem"
      key_file: "/path/to/api-key.pem"
    locations:
      - path: "/api/" # served path suffix so "https://internal-api1.local.com/api/"
        lb_policy: round-robin # load balancing policy
        http_redirect: true # http to https redirect
        redirect: "/" # redirect e.q. from "/" to "/api/"
        backends:
          - url: http://internal-api1.local.com:8455
            weight: 5
            max_connections: 1000
          - url: http://internal-api2.local.com:8455
            weight: 3
            max_connections: 800

  - name: frontend
    host: frontend.local.com
    locations:
      - path: "/"
        lb_policy: least_connections
        http_redirect: false
        rewrite: "/frontend/" # rewrite e.q. from "/" to "/frontend/" in the backend service
        backends:
          - url: http://frontend-1.local.com:3000
            weight: 5
            max_connections: 1000

          - url: http://frontend-2.local.com:3000
            weight: 3
            max_connections: 800

health_check:
  interval: 10s
  timeout: 2s
  path: /health
  thresholds:
    healthy: 2
    unhealthy: 3

# api authentication
auth:
  jwt_secret: mySecretKey
  db_path: ./auth.db
  password_expiry_days: 7
  password_history_size: 5

admin_api:
  rate_limit:
    requests_per_second: 10
    burst: 20

rate_limit:
  requests_per_second: 100
  burst: 150

connection_pool:
  max_idle: 100
  max_open: 1000
  idle_timeout: 90s
```

3. Run the load balancer:
```bash
./terraster --config config.yaml
```

## Configuration Examples

### Basic Configuration
```yaml
port: 8080
algorithm: round-robin
backends:
  - url: http://localhost:8081
  - url: http://localhost:8082
```

### Advanced Configuration
```yaml
port: 8080
admin_port: 8081
algorithm: adaptive

tls:
  enabled: true
  domains:
    - example.com
  cert_dir: /etc/certs
  auto_cert: true

rate_limit:
  requests_per_second: 1000
  burst: 50

circuit_breaker:
  threshold: 5
  timeout: 60s

connection_pool:
  max_idle: 100
  max_open: 1000
  idle_timeout: 90s

cors:
  allowed_origins:
    - https://example.com
  allowed_methods:
    - GET
    - POST
  allowed_headers:
    - Content-Type
  max_age: 3600

security:
  hsts: true
  hsts_max_age: 31536000
  frame_options: DENY
  content_type_options: true
  xss_protection: true
```
## API Examples

### Admin API

1. Get Backend Status:
```bash
curl http://localhost:8081/api/backends \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1..." \
    -H "Content-Type: application/json"
```

2. Add Backend:
```bash
curl -X POST http://localhost:8081/api/backends \
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
