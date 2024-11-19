package server

import (
	"crypto/tls"
	"net"
	"strconv"
	"strings"
)

func (s *Server) hostNameNoPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return ""
	}

	return h
}

func (s *Server) servicePort(port int) int {
	if port != 0 {
		return port
	}

	return DefaultHTTPPort
}

func parseHostPort(hostPort string, tlsState *tls.ConnectionState) (host string, port int, err error) {
	// Fast path for common case: no port specified
	if !strings.Contains(hostPort, ":") {
		if tlsState != nil {
			return hostPort, DefaultHTTPSPort, nil
		}
		return hostPort, DefaultHTTPPort, nil
	}

	// Slow path: parse host:port
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
