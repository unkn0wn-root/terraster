package server

import (
	"crypto/tls"
	"net"
	"strconv"
)

func parseHostPort(hostPort string, tlsState *tls.ConnectionState) (host string, port int, err error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, err
	}

	// if no port, we have to assume that request is either http or https
	// so based on the protocol we can determine the port to use
	pn, err := strconv.Atoi(portStr)
	if err != nil || pn == 0 {
		if tlsState != nil {
			pn = DefaultHTTPSPort
		} else {
			pn = DefaultHTTPPort
		}
	}

	return host, pn, nil
}
