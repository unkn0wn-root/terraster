package server

import (
	"crypto/tls"
	"net"
	"strconv"
)

func parseHostPort(hostPort string, tlsState *tls.ConnectionState) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}

	// portStr will be empty if there is no port in the hostPort string
	// we have to assume that request is either http or https on standard port
	var pn int
	if portStr == "" {
		pn = 0
	} else {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, err
		}

		pn = p
	}

	// if port is 0, then assign standard http or https port
	if pn == 0 {
		if tlsState != nil {
			pn = DefaultHTTPSPort
		} else {
			pn = DefaultHTTPPort
		}
	}

	return host, pn, nil
}
