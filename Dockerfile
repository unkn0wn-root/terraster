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
