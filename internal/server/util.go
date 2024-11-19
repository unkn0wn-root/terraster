package server

import (
	"crypto/tls"
	"net"
	"strconv"
)

func parseHostPort(hostPort string, tlsState *tls.ConnectionState) (host string, port int, err error) {
	host, portStr, _ := net.SplitHostPort(hostPort)
	// if no port, we have to assume that request is either http or https
	// so based on the protocol we can determine the port to use
	pn, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}

	// if port is 0, it is because incoming request is on standard http or https port
	// and portStr will return empty string which then means that pn will be 0
	if pn == 0 {
		if tlsState != nil {
			pn = DefaultHTTPSPort
		} else {
			pn = DefaultHTTPPort
		}
	}

	return host, pn, nil
}
