package server

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
)

// hostNameNoPort extracts the hostname from a given host string by removing the port.
// If the host string does not contain a port, it returns an empty string.
//
// Parameters:
// - host: A string representing the host, potentially including a port (e.g., "example.com:8080").
//
// Returns:
// - string: The hostname without the port (e.g., "example.com"). Returns an empty string if parsing fails.
func (s *Server) hostNameNoPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return ""
	}

	return h
}

// servicePort determines the port number to use for a service.
// If a specific port is provided (non-zero), it returns that port.
// Otherwise, it defaults to the standard HTTP port.
//
// Parameters:
// - port: An integer representing the desired port number.
//
// Returns:
// - int: The port number to use for the service.
func (s *Server) servicePort(port int) int {
	if port != 0 {
		return port
	}

	return DefaultHTTPPort
}

// hasHTTPSRedirects checks if any of the configured services require HTTP to HTTPS redirection.
// Returns true if at least one service has HTTP redirects enabled, otherwise false.
func (s *Server) hasHTTPSRedirects() bool {
	services := s.serviceManager.GetServices()
	for _, service := range services {
		if service.HTTPRedirect {
			return true
		}
	}
	return false
}

// parseHostPort parses a combined host and port string and determines the appropriate port based on TLS state.
// If the host string does not contain a port, it assigns a default port based on whether TLS is enabled.
//
// Parameters:
// - hostPort: A string containing the host and optionally the port (e.g., "example.com:443").
// - tlsState: A pointer to tls.ConnectionState which indicates if the connection is using TLS.
//
// Returns:
// - host: The extracted hostname without the port.
// - port: The determined port number (either extracted from the hostPort or a default based on TLS).
// - err: An error if the hostPort string is malformed or the port is not a valid integer.
func parseHostPort(hostPort string, tlsState *tls.ConnectionState) (host string, port int, err error) {
	if !strings.Contains(hostPort, ":") {
		if tlsState != nil {
			return hostPort, DefaultHTTPSPort, nil
		}
		return hostPort, DefaultHTTPPort, nil
	}

	// Slow path: parse the host and port from the hostPort string.
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, err
	}

	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}

	return host, port, nil
}
