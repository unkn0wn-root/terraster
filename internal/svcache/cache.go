package svcache

import (
	"fmt"

	"github.com/unkn0wn-root/terraster/internal/service"
)

// ServiceKey uniquely identifies a service within the Terraster application.
// It is composed of the service's host, port, and protocol, ensuring that each service
// can be distinctly referenced and managed within the system.
type ServiceKey struct {
	Host     string              // The hostname where the service is accessible, e.g., "api.example.com".
	Port     int                 // The port number on which the service listens, e.g., 80 for HTTP or 443 for HTTPS.
	Protocol service.ServiceType // The protocol used by the service, either HTTP or HTTPS, determining how requests are handled.
}

// String generates a standardized string representation of the ServiceKey.
// This format concatenates the Host, Port, and Protocol fields separated by pipes ("|"),
// resulting in a string like "api.example.com|443|https". This representation is particularly
// useful for creating unique keys for maps or caches, ensuring that each service can be
// efficiently and accurately retrieved based on its unique identifier.
func (k ServiceKey) String() string {
	return fmt.Sprintf("%s|%d|%s", k.Host, k.Port, k.Protocol)
}
